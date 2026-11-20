package com.blueops.detections.sigma;

import com.blueops.findings.FindingDto;
import com.blueops.telemetry.NormalizedEvent;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.util.*;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Dynamic Sigma Detection Evaluator (DET-001)
 * Evaluates streaming normalized telemetry events against active declarative Sigma rules,
 * performing logsource routing, selection matching, and condition evaluation.
 */
@Service
public class SigmaDetectionEvaluator {

    private static final Logger log = LoggerFactory.getLogger(SigmaDetectionEvaluator.class);

    private final SigmaRuleRegistry ruleRegistry;
    private final SigmaFieldMatcher fieldMatcher;
    private final SigmaConditionEvaluator conditionEvaluator;
    private final AtomicLong findingSeq = new AtomicLong(2000);

    public SigmaDetectionEvaluator(
            SigmaRuleRegistry ruleRegistry,
            SigmaFieldMatcher fieldMatcher,
            SigmaConditionEvaluator conditionEvaluator) {
        this.ruleRegistry = ruleRegistry;
        this.fieldMatcher = fieldMatcher;
        this.conditionEvaluator = conditionEvaluator;
    }

    /**
     * Evaluates a normalized event against all active registered Sigma rules.
     */
    public List<FindingDto> evaluate(NormalizedEvent event, String assetId, String assetName) {
        List<FindingDto> triggered = new ArrayList<>();
        if (event == null || ruleRegistry == null) return triggered;

        List<SigmaRuleDefinition> activeRules = ruleRegistry.getAllRules();
        if (activeRules.isEmpty()) return triggered;

        String eventOs = determineEventOs(event);

        for (SigmaRuleDefinition rule : activeRules) {
            try {
                if (!matchesLogSource(rule.getLogsource(), event, eventOs)) {
                    continue;
                }

                Map<String, Object> detection = rule.getDetection();
                if (detection == null || detection.isEmpty()) {
                    continue;
                }

                Object condObj = detection.get("condition");
                if (condObj == null) {
                    continue;
                }
                String condition = String.valueOf(condObj);

                // 1. Evaluate all selection criteria maps
                Map<String, Boolean> selectionOutcomes = new HashMap<>();
                for (Map.Entry<String, Object> entry : detection.entrySet()) {
                    String key = entry.getKey();
                    if ("condition".equalsIgnoreCase(key) || "timeframe".equalsIgnoreCase(key)) {
                        continue;
                    }

                    if (entry.getValue() instanceof Map<?, ?> criteriaMap) {
                        @SuppressWarnings("unchecked")
                        Map<String, Object> typedCriteria = (Map<String, Object>) criteriaMap;
                        boolean outcome = fieldMatcher.matchesSelection(typedCriteria, event);
                        selectionOutcomes.put(key, outcome);
                    }
                }

                // 2. Evaluate condition expression
                boolean matched = conditionEvaluator.evaluate(condition, selectionOutcomes);
                if (matched) {
                    FindingDto finding = buildFinding(rule, event, assetId, assetName, condition);
                    triggered.add(finding);
                    log.info("Dynamic Sigma Rule Triggered: [{}] '{}' (Level: {}) on asset '{}'",
                            rule.getRuleCode(), rule.getTitle(), rule.getLevel(), assetId);
                }
            } catch (Exception ex) {
                log.debug("Error evaluating Sigma rule [{}] against event: {}", rule.getRuleCode(), ex.getMessage());
            }
        }

        return triggered;
    }

    private boolean matchesLogSource(Map<String, Object> logsource, NormalizedEvent event, String eventOs) {
        if (logsource == null || logsource.isEmpty()) return true;

        Object productObj = logsource.get("product");
        if (productObj != null) {
            String requiredProduct = String.valueOf(productObj).toLowerCase(Locale.ROOT);
            if (!requiredProduct.equalsIgnoreCase("any")) {
                if (eventOs != null && !eventOs.equalsIgnoreCase("unknown")) {
                    if (!eventOs.toLowerCase(Locale.ROOT).contains(requiredProduct)) {
                        return false;
                    }
                }
            }
        }

        return true;
    }

    private String determineEventOs(NormalizedEvent event) {
        if (event.getHost() != null && event.getHost().getOsName() != null) {
            String os = event.getHost().getOsName().toLowerCase(Locale.ROOT);
            if (os.contains("win")) return "windows";
            if (os.contains("linux") || os.contains("ubuntu") || os.contains("debian") || os.contains("centos")) return "linux";
        }
        if (event.getEvent() != null && event.getEvent().getProvider() != null) {
            String provider = event.getEvent().getProvider().toLowerCase(Locale.ROOT);
            if (provider.contains("sysmon") || provider.contains("windows")) return "windows";
            if (provider.contains("audit") || provider.contains("syslog") || provider.contains("linux")) return "linux";
            if (provider.contains("suricata")) return "network";
        }
        return "unknown";
    }

    private FindingDto buildFinding(SigmaRuleDefinition rule, NormalizedEvent event, String assetId, String assetName, String condition) {
        String fId = "FND-SIGMA-" + (rule.getRuleCode() != null ? rule.getRuleCode() : "GEN") + "-" + findingSeq.incrementAndGet();
        String ruleCode = rule.getRuleCode() != null ? rule.getRuleCode() : "SIGMA";
        String title = rule.getTitle() != null ? rule.getTitle() : "Sigma Detection Rule Matched";
        String level = rule.getLevel() != null ? rule.getLevel().toUpperCase(Locale.ROOT) : "MEDIUM";
        String tactic = rule.getMitreTactic() != null ? rule.getMitreTactic() : "Execution";
        String techniqueId = rule.getMitreTechniqueId() != null ? rule.getMitreTechniqueId() : "T1059";
        String techniqueDesc = rule.getDescription() != null ? rule.getDescription() : "Declarative Sigma Detection";

        Map<String, Object> details = new HashMap<>();
        details.put("sigma_rule_id", rule.getId());
        details.put("rule_code", ruleCode);
        details.put("rule_title", title);
        details.put("condition", condition);
        details.put("rule_file", rule.getSourceFilePath());

        if (event.getProcess() != null) {
            if (event.getProcess().getCommandLine() != null) details.put("command_line", event.getProcess().getCommandLine());
            if (event.getProcess().getName() != null) details.put("process_name", event.getProcess().getName());
        }
        if (event.getFile() != null && event.getFile().getPath() != null) {
            details.put("file_path", event.getFile().getPath());
        }

        return new FindingDto(
                fId, ruleCode, title, level, tactic, techniqueId, techniqueDesc,
                assetId != null ? assetId : "UNKNOWN-ASSET",
                assetName != null ? assetName : "UNKNOWN-HOST",
                event.getTimestamp() != null ? event.getTimestamp() : java.time.Instant.now(),
                "UNASSIGNED",
                event.getId(),
                details
        );
    }
}
