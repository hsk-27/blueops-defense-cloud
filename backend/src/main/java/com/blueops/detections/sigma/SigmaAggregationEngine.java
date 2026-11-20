package com.blueops.detections.sigma;

import com.blueops.telemetry.NormalizedEvent;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.time.Instant;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Sigma Aggregation Engine (DET-003)
 * Provides stateful sliding-window count aggregation and sequence evaluation
 * for multi-event Sigma detection rules (e.g. '| count(event.id) by source.ip > 5',
 * 'selection_fail and selection_success by source.ip').
 * Eliminates false positive floods caused by naive aggregation stripping.
 */
@Component
public class SigmaAggregationEngine {

    private static final Logger log = LoggerFactory.getLogger(SigmaAggregationEngine.class);

    // Regex for pipeline count aggregations: e.g. "selection | count(event.id) by source.ip > 5"
    private static final Pattern COUNT_AGGREGATION_PATTERN = Pattern.compile(
            "^\\s*(.*?)\\s*\\|\\s*count\\(([^)]*)\\)(?:\\s+by\\s+([a-zA-Z0-9._]+))?\\s*(>|>=|==|<|<=)\\s*(\\d+)\\s*$",
            Pattern.CASE_INSENSITIVE
    );

    // Regex for sequence correlation: e.g. "selection_fail and selection_success by source.ip"
    private static final Pattern SEQUENCE_BY_PATTERN = Pattern.compile(
            "^\\s*(.*?)\\s+by\\s+([a-zA-Z0-9._]+)\\s*$",
            Pattern.CASE_INSENSITIVE
    );

    // Map: "ruleCode:entityKey" -> Deque of epoch millisecond timestamps
    private final Map<String, Deque<Long>> countWindows = new ConcurrentHashMap<>();

    // Map: "ruleCode:entityKey" -> Timestamp of last observed preliminary stage (e.g. failure before success)
    private final Map<String, Long> sequenceStates = new ConcurrentHashMap<>();

    private static final int MAX_TRACKED_ENTITIES = 5000;

    /**
     * Determines whether the given condition expression contains an aggregation or sequence clause.
     */
    public boolean hasAggregation(String condition) {
        if (condition == null || condition.isBlank()) return false;
        return condition.contains("|") || SEQUENCE_BY_PATTERN.matcher(condition.trim()).matches();
    }

    /**
     * Evaluates a multi-event aggregation rule against incoming event and selection outcomes.
     * Returns true ONLY if the stateful threshold or sequence transition is satisfied.
     */
    public boolean evaluateAggregation(
            SigmaRuleDefinition rule,
            NormalizedEvent event,
            Map<String, Boolean> selectionOutcomes,
            SigmaConditionEvaluator conditionEvaluator) {

        String condition = rule.getDetection() != null && rule.getDetection().get("condition") != null
                ? String.valueOf(rule.getDetection().get("condition")).trim()
                : "";

        long now = event.getTimestamp() != null ? event.getTimestamp().toEpochMilli() : System.currentTimeMillis();
        String timeframe = rule.getDetection() != null && rule.getDetection().get("timeframe") != null
                ? String.valueOf(rule.getDetection().get("timeframe"))
                : "5m";
        long windowMillis = parseTimeframeMillis(timeframe);

        // 1. Check for count aggregation: "<expr> | count(...) by <entity> > <threshold>"
        Matcher countMatcher = COUNT_AGGREGATION_PATTERN.matcher(condition);
        if (countMatcher.matches()) {
            String baseExpr = countMatcher.group(1).trim();
            String byField = countMatcher.group(3);
            String operator = countMatcher.group(4);
            int threshold = Integer.parseInt(countMatcher.group(5));

            // Evaluate the base selection expression
            boolean baseMatches = conditionEvaluator.evaluate(baseExpr, selectionOutcomes);
            if (!baseMatches) {
                return false;
            }

            String entityKey = extractEntityKey(event, byField);
            String stateKey = rule.getRuleCode() + ":" + entityKey;

            synchronized (countWindows) {
                pruneOldEntitiesIfCapacityExceeded();
                Deque<Long> window = countWindows.computeIfAbsent(stateKey, k -> new ArrayDeque<>());

                // Prune timestamps older than window
                long cutoff = now - windowMillis;
                while (!window.isEmpty() && window.peekFirst() < cutoff) {
                    window.pollFirst();
                }

                window.addLast(now);
                int count = window.size();

                boolean thresholdMet = switch (operator) {
                    case ">" -> count > threshold;
                    case ">=" -> count >= threshold;
                    case "==" -> count == threshold;
                    case "<" -> count < threshold;
                    case "<=" -> count <= threshold;
                    default -> count > threshold;
                };

                if (thresholdMet) {
                    log.info("Sigma Aggregation Rule [{}] threshold met for entity '{}': count={} {} {}",
                            rule.getRuleCode(), entityKey, count, operator, threshold);
                }

                return thresholdMet;
            }
        }

        // 2. Check for sequence correlation: "selection_fail and selection_success by <entity>"
        Matcher seqMatcher = SEQUENCE_BY_PATTERN.matcher(condition);
        if (seqMatcher.matches()) {
            String byField = seqMatcher.group(2);
            String entityKey = extractEntityKey(event, byField);
            String stateKey = rule.getRuleCode() + ":" + entityKey;

            boolean failMatched = Boolean.TRUE.equals(selectionOutcomes.get("selection_fail"));
            boolean successMatched = Boolean.TRUE.equals(selectionOutcomes.get("selection_success"));

            synchronized (sequenceStates) {
                if (failMatched) {
                    sequenceStates.put(stateKey, now);
                    return false; // Preliminary stage observed; await subsequent success
                }

                if (successMatched) {
                    Long lastFailTime = sequenceStates.get(stateKey);
                    if (lastFailTime != null && (now - lastFailTime) <= windowMillis) {
                        // Sequence completed: success followed failures within window
                        sequenceStates.remove(stateKey); // Consume state to prevent duplicate triggers
                        log.info("Sigma Sequence Rule [{}] matched for entity '{}': success following failures within {}ms",
                                rule.getRuleCode(), entityKey, (now - lastFailTime));
                        return true;
                    }
                }
            }

            return false;
        }

        // Fallback for non-aggregation conditions
        return conditionEvaluator.evaluate(condition, selectionOutcomes);
    }

    public String extractEntityKey(NormalizedEvent event, String field) {
        if (event == null) return "unknown";
        if (field == null || field.isBlank()) {
            if (event.getHost() != null && event.getHost().getIp() != null) return event.getHost().getIp();
            return "global";
        }

        String f = field.toLowerCase(Locale.ROOT);
        if (f.contains("source.ip") || f.contains("src_ip")) {
            if (event.getSource() != null && event.getSource().getIp() != null) {
                return event.getSource().getIp();
            }
            if (event.getHost() != null && event.getHost().getIp() != null) {
                return event.getHost().getIp();
            }
        } else if (f.contains("user.name") || f.contains("user")) {
            if (event.getUser() != null && event.getUser().getName() != null) {
                return event.getUser().getName();
            }
        } else if (f.contains("dest_ip") || f.contains("destination.ip")) {
            if (event.getDestination() != null && event.getDestination().getIp() != null) {
                return event.getDestination().getIp();
            }
        }

        return event.getHost() != null && event.getHost().getName() != null
                ? event.getHost().getName()
                : "unknown-entity";
    }

    public long parseTimeframeMillis(String timeframe) {
        if (timeframe == null || timeframe.isBlank()) {
            return 300_000L; // Default 5 minutes
        }
        String t = timeframe.trim().toLowerCase(Locale.ROOT);
        try {
            if (t.endsWith("s")) {
                return Long.parseLong(t.substring(0, t.length() - 1)) * 1000L;
            } else if (t.endsWith("m")) {
                return Long.parseLong(t.substring(0, t.length() - 1)) * 60_000L;
            } else if (t.endsWith("h")) {
                return Long.parseLong(t.substring(0, t.length() - 1)) * 3_600_000L;
            } else if (t.endsWith("d")) {
                return Long.parseLong(t.substring(0, t.length() - 1)) * 86_400_000L;
            } else {
                return Long.parseLong(t) * 1000L;
            }
        } catch (NumberFormatException e) {
            return 300_000L;
        }
    }

    private void pruneOldEntitiesIfCapacityExceeded() {
        if (countWindows.size() > MAX_TRACKED_ENTITIES) {
            countWindows.clear();
        }
        if (sequenceStates.size() > MAX_TRACKED_ENTITIES) {
            sequenceStates.clear();
        }
    }

    public void reset() {
        countWindows.clear();
        sequenceStates.clear();
    }
}
