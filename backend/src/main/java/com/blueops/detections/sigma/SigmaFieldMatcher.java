package com.blueops.detections.sigma;

import com.blueops.telemetry.NormalizedEvent;
import org.springframework.stereotype.Component;

import java.util.*;
import java.util.regex.Pattern;

/**
 * Sigma Field Matcher (DET-003)
 * Extracts normalized event attributes and evaluates Sigma selection criteria,
 * supporting field modifiers (|contains, |endswith, |startswith, |re), wildcards, and list semantics.
 */
@Component
public class SigmaFieldMatcher {

    /**
     * Evaluates a selection criteria map against a normalized event.
     * All criteria within a single selection map are evaluated with AND semantics.
     */
    public boolean matchesSelection(Map<String, Object> criteria, NormalizedEvent event) {
        if (criteria == null || criteria.isEmpty()) return true;
        if (event == null) return false;

        for (Map.Entry<String, Object> entry : criteria.entrySet()) {
            String rawKey = entry.getKey();
            Object expectedValue = entry.getValue();

            String fieldName = rawKey;
            String modifier = "exact";

            if (rawKey.contains("|")) {
                String[] parts = rawKey.split("\\|", 2);
                fieldName = parts[0].trim();
                modifier = parts[1].trim().toLowerCase(Locale.ROOT);
            }

            List<String> actualValues = extractFieldValues(fieldName, event);
            if (actualValues.isEmpty()) {
                // If the event does not contain the field, the selection cannot match
                return false;
            }

            boolean fieldMatched = matchesField(actualValues, expectedValue, modifier);
            if (!fieldMatched) {
                return false;
            }
        }

        return true;
    }

    /**
     * Checks if any of the actual event field values match the expected Sigma value(s)
     * using the specified modifier.
     */
    public boolean matchesField(List<String> actualValues, Object expectedValue, String modifier) {
        if (expectedValue instanceof List<?> expectedList) {
            // Sigma list semantics: OR condition across list elements
            for (Object item : expectedList) {
                if (item != null && matchesSingleValue(actualValues, String.valueOf(item), modifier)) {
                    return true;
                }
            }
            return false;
        } else if (expectedValue != null) {
            return matchesSingleValue(actualValues, String.valueOf(expectedValue), modifier);
        }
        return false;
    }

    private boolean matchesSingleValue(List<String> actualValues, String expected, String modifier) {
        String normalizedExpected = normalizePathSlashes(expected);

        for (String actual : actualValues) {
            if (actual == null) continue;
            String normalizedActual = normalizePathSlashes(actual);

            switch (modifier) {
                case "contains" -> {
                    if (wildcardOrSubstringMatch(normalizedActual, normalizedExpected, true)) {
                        return true;
                    }
                }
                case "endswith" -> {
                    if (normalizedActual.toLowerCase(Locale.ROOT).endsWith(normalizedExpected.toLowerCase(Locale.ROOT))) {
                        return true;
                    }
                    // Handle file extension or basename match (e.g. '\powershell.exe' matches 'powershell.exe')
                    if (normalizedExpected.startsWith("/") && normalizedActual.toLowerCase(Locale.ROOT).endsWith(normalizedExpected.substring(1).toLowerCase(Locale.ROOT))) {
                        return true;
                    }
                }
                case "startswith" -> {
                    if (normalizedActual.toLowerCase(Locale.ROOT).startsWith(normalizedExpected.toLowerCase(Locale.ROOT))) {
                        return true;
                    }
                }
                case "re" -> {
                    try {
                        Pattern pattern = Pattern.compile(expected, Pattern.CASE_INSENSITIVE);
                        if (pattern.matcher(actual).find()) {
                            return true;
                        }
                    } catch (Exception ignored) {}
                }
                default -> { // exact
                    if (normalizedActual.equalsIgnoreCase(normalizedExpected)) {
                        return true;
                    }
                    // Fallback to wildcard matching if expected contains '*' or '?'
                    if (expected.contains("*") || expected.contains("?")) {
                        if (wildcardMatch(normalizedActual, normalizedExpected)) {
                            return true;
                        }
                    }
                }
            }
        }
        return false;
    }

    /**
     * Extracts string candidates from the NormalizedEvent for a given Sigma field name.
     */
    public List<String> extractFieldValues(String fieldName, NormalizedEvent event) {
        List<String> values = new ArrayList<>();
        if (fieldName == null || event == null) return values;

        String key = fieldName.toLowerCase(Locale.ROOT).replace("_", "").replace(".", "");

        // Process fields
        if (key.equals("image") || key.equals("processexecutable") || key.equals("processname")) {
            if (event.getProcess() != null) {
                if (event.getProcess().getExecutable() != null) values.add(event.getProcess().getExecutable());
                if (event.getProcess().getName() != null) values.add(event.getProcess().getName());
            }
        } else if (key.equals("commandline") || key.equals("processcommandline")) {
            if (event.getProcess() != null && event.getProcess().getCommandLine() != null) {
                values.add(event.getProcess().getCommandLine());
            }
        } else if (key.equals("parentimage") || key.equals("processparentexecutable") || key.equals("processparentname")) {
            if (event.getProcess() != null && event.getProcess().getParent() != null) {
                if (event.getProcess().getParent().getExecutable() != null) values.add(event.getProcess().getParent().getExecutable());
                if (event.getProcess().getParent().getName() != null) values.add(event.getProcess().getParent().getName());
            }
        } else if (key.equals("parentcommandline") || key.equals("processparentcommandline")) {
            if (event.getProcess() != null && event.getProcess().getParent() != null && event.getProcess().getParent().getCommandLine() != null) {
                values.add(event.getProcess().getParent().getCommandLine());
            }
        } else if (key.equals("targetimage") || key.equals("sourceimage")) {
            if (event.getProcess() != null) {
                if (event.getProcess().getName() != null) values.add(event.getProcess().getName());
                if (event.getProcess().getCommandLine() != null) values.add(event.getProcess().getCommandLine());
            }
            if (event.getFile() != null && event.getFile().getPath() != null) {
                values.add(event.getFile().getPath());
            }
        } else if (key.equals("targetfilename") || key.equals("filepath") || key.equals("filename") || key.equals("imageloaded")) {
            if (event.getFile() != null) {
                if (event.getFile().getPath() != null) values.add(event.getFile().getPath());
                if (event.getFile().getName() != null) values.add(event.getFile().getName());
            }
            if (event.getProcess() != null && event.getProcess().getCommandLine() != null) {
                values.add(event.getProcess().getCommandLine());
            }
        } else if (key.equals("eventaction") || key.equals("eventoutcome") || key.equals("action")) {
            if (event.getEvent() != null) {
                if (event.getEvent().getAction() != null) values.add(event.getEvent().getAction());
                if (event.getEvent().getCategory() != null) values.addAll(event.getEvent().getCategory());
            }
        } else if (key.equals("sourceip") || key.equals("srcip")) {
            if (event.getSource() != null && event.getSource().getIp() != null) {
                values.add(event.getSource().getIp());
            }
        } else if (key.equals("destinationip") || key.equals("destip")) {
            if (event.getDestination() != null && event.getDestination().getIp() != null) {
                values.add(event.getDestination().getIp());
            }
        } else if (key.equals("destinationport") || key.equals("destport")) {
            if (event.getDestination() != null && event.getDestination().getPort() != null) {
                values.add(String.valueOf(event.getDestination().getPort()));
            }
        } else if (key.equals("username") || key.equals("user")) {
            if (event.getUser() != null && event.getUser().getName() != null) {
                values.add(event.getUser().getName());
            }
        } else if (key.equals("grantedaccess")) {
            if (event.getEvent() != null && event.getEvent().getOriginal() != null) {
                values.add(event.getEvent().getOriginal());
            }
        }

        // Fallback: check original payload if field is still empty
        if (values.isEmpty() && event.getEvent() != null && event.getEvent().getOriginal() != null) {
            values.add(event.getEvent().getOriginal());
        }

        return values;
    }

    private static String normalizePathSlashes(String path) {
        if (path == null) return "";
        return path.replace("\\", "/");
    }

    private static boolean wildcardOrSubstringMatch(String text, String pattern, boolean containsMode) {
        if (pattern.contains("*") || pattern.contains("?")) {
            return wildcardMatch(text, pattern);
        }
        if (containsMode) {
            return text.toLowerCase(Locale.ROOT).contains(pattern.toLowerCase(Locale.ROOT));
        }
        return text.equalsIgnoreCase(pattern);
    }

    public static boolean wildcardMatch(String text, String globPattern) {
        if (text == null || globPattern == null) return false;
        // Convert glob wildcard (* -> .*, ? -> .) to regex
        StringBuilder sb = new StringBuilder("(?i)");
        for (int i = 0; i < globPattern.length(); i++) {
            char c = globPattern.charAt(i);
            if (c == '*') {
                sb.append(".*");
            } else if (c == '?') {
                sb.append(".");
            } else if ("\\.[]{}()+-^$|".indexOf(c) != -1) {
                sb.append("\\").append(c);
            } else {
                sb.append(c);
            }
        }
        try {
            return Pattern.compile(sb.toString()).matcher(text).find();
        } catch (Exception e) {
            return text.toLowerCase(Locale.ROOT).contains(globPattern.toLowerCase(Locale.ROOT));
        }
    }
}
