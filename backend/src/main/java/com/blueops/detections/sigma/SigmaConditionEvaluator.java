package com.blueops.detections.sigma;

import org.springframework.stereotype.Component;

import java.util.*;

/**
 * Sigma Condition Evaluator (DET-002)
 * Compiles and evaluates Sigma boolean condition algebra expressions:
 * supports 'and', 'or', 'not', parentheses, wildcards ('1 of selection*'),
 * and aggregation expression stripping.
 */
@Component
public class SigmaConditionEvaluator {

    /**
     * Evaluates a Sigma condition expression against a map of evaluated selection outcomes.
     */
    public boolean evaluate(String conditionExpression, Map<String, Boolean> selectionOutcomes) {
        if (conditionExpression == null || conditionExpression.isBlank()) {
            return false;
        }

        String sanitized = preprocessCondition(conditionExpression);
        List<String> tokens = tokenize(sanitized);
        if (tokens.isEmpty()) {
            return false;
        }

        Parser parser = new Parser(tokens, selectionOutcomes != null ? selectionOutcomes : Collections.emptyMap());
        return parser.parseExpression();
    }

    /**
     * Strips pipeline aggregations (e.g. '| count(event.id) > 5') and trailing 'by ...' clauses
     * for single-event condition evaluation.
     */
    public String preprocessCondition(String condition) {
        String result = condition.trim();

        // 1. Strip aggregation expressions after pipe '|'
        if (result.contains("|")) {
            result = result.substring(0, result.indexOf('|')).trim();
        }

        // 2. Strip trailing 'by <field>' clauses
        int byIdx = result.toLowerCase(Locale.ROOT).lastIndexOf(" by ");
        if (byIdx != -1) {
            result = result.substring(0, byIdx).trim();
        }

        return result;
    }

    private List<String> tokenize(String input) {
        List<String> tokens = new ArrayList<>();
        StringBuilder current = new StringBuilder();

        for (int i = 0; i < input.length(); i++) {
            char c = input.charAt(i);

            if (Character.isWhitespace(c)) {
                if (!current.isEmpty()) {
                    tokens.add(current.toString());
                    current.setLength(0);
                }
            } else if (c == '(' || c == ')') {
                if (!current.isEmpty()) {
                    tokens.add(current.toString());
                    current.setLength(0);
                }
                tokens.add(String.valueOf(c));
            } else {
                current.append(c);
            }
        }

        if (!current.isEmpty()) {
            tokens.add(current.toString());
        }

        return tokens;
    }

    private static class Parser {
        private final List<String> tokens;
        private final Map<String, Boolean> outcomes;
        private int pos = 0;

        public Parser(List<String> tokens, Map<String, Boolean> outcomes) {
            this.tokens = tokens;
            this.outcomes = outcomes;
        }

        public boolean parseExpression() {
            return parseOr();
        }

        private boolean parseOr() {
            boolean result = parseAnd();
            while (match("or")) {
                boolean right = parseAnd();
                result = result || right;
            }
            return result;
        }

        private boolean parseAnd() {
            boolean result = parseNot();
            while (match("and")) {
                boolean right = parseNot();
                result = result && right;
            }
            return result;
        }

        private boolean parseNot() {
            if (match("not")) {
                return !parseNot();
            }
            return parsePrimary();
        }

        private boolean parsePrimary() {
            if (match("(")) {
                boolean result = parseExpression();
                consume(")");
                return result;
            }

            // Check for quantifier expressions: "1 of selection*", "all of selection*", "1 of them"
            if (peek() != null && (peek().equalsIgnoreCase("1") || peek().equalsIgnoreCase("all"))) {
                String quant = next();
                if (match("of")) {
                    String targetPattern = next();
                    return evaluateQuantifier(quant, targetPattern);
                }
            }

            String identifier = next();
            if (identifier == null) {
                return false;
            }

            // Direct lookup in selection outcomes map
            if (outcomes.containsKey(identifier)) {
                return Boolean.TRUE.equals(outcomes.get(identifier));
            }

            // Case-insensitive fallback
            for (Map.Entry<String, Boolean> entry : outcomes.entrySet()) {
                if (entry.getKey().equalsIgnoreCase(identifier)) {
                    return Boolean.TRUE.equals(entry.getValue());
                }
            }

            return false;
        }

        private boolean evaluateQuantifier(String quant, String pattern) {
            if (pattern == null) return false;
            boolean isAll = quant.equalsIgnoreCase("all");

            List<Boolean> matchedValues = new ArrayList<>();
            if (pattern.equalsIgnoreCase("them")) {
                matchedValues.addAll(outcomes.values());
            } else if (pattern.endsWith("*")) {
                String prefix = pattern.substring(0, pattern.length() - 1).toLowerCase(Locale.ROOT);
                for (Map.Entry<String, Boolean> entry : outcomes.entrySet()) {
                    if (entry.getKey().toLowerCase(Locale.ROOT).startsWith(prefix)) {
                        matchedValues.add(entry.getValue());
                    }
                }
            } else {
                if (outcomes.containsKey(pattern)) {
                    matchedValues.add(outcomes.get(pattern));
                }
            }

            if (matchedValues.isEmpty()) return false;

            if (isAll) {
                return matchedValues.stream().allMatch(Boolean.TRUE::equals);
            } else {
                return matchedValues.stream().anyMatch(Boolean.TRUE::equals);
            }
        }

        private boolean match(String expected) {
            if (pos < tokens.size() && tokens.get(pos).equalsIgnoreCase(expected)) {
                pos++;
                return true;
            }
            return false;
        }

        private void consume(String expected) {
            if (pos < tokens.size() && tokens.get(pos).equalsIgnoreCase(expected)) {
                pos++;
            }
        }

        private String peek() {
            if (pos < tokens.size()) return tokens.get(pos);
            return null;
        }

        private String next() {
            if (pos < tokens.size()) {
                return tokens.get(pos++);
            }
            return null;
        }
    }
}
