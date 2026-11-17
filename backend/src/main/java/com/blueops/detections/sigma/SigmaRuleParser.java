package com.blueops.detections.sigma;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;
import org.yaml.snakeyaml.Yaml;

import java.io.InputStream;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Parses Sigma YAML rule files into strongly typed SigmaRuleDefinition objects.
 */
@Component
public class SigmaRuleParser {

    private static final Logger log = LoggerFactory.getLogger(SigmaRuleParser.class);
    private static final Pattern CODE_FROM_NAME_PATTERN = Pattern.compile("^(D[0-9]{3})_");
    private static final Pattern TECHNIQUE_TAG_PATTERN = Pattern.compile("^attack\\.(t[0-9]+(?:\\.[0-9]+)?)$", Pattern.CASE_INSENSITIVE);

    public SigmaRuleDefinition parse(InputStream inputStream, String filename) {
        Yaml yaml = new Yaml();
        Map<String, Object> data = yaml.load(inputStream);
        return mapToDefinition(data, filename);
    }

    public SigmaRuleDefinition parse(String yamlContent, String filename) {
        Yaml yaml = new Yaml();
        Map<String, Object> data = yaml.load(yamlContent);
        return mapToDefinition(data, filename);
    }

    @SuppressWarnings("unchecked")
    private SigmaRuleDefinition mapToDefinition(Map<String, Object> data, String filename) {
        if (data == null) {
            throw new IllegalArgumentException("Sigma YAML content is empty or malformed");
        }

        SigmaRuleDefinition rule = new SigmaRuleDefinition();
        rule.setSourceFilePath(filename);
        rule.setTitle((String) data.get("title"));
        rule.setId(String.valueOf(data.get("id")));
        rule.setStatus((String) data.get("status"));
        rule.setDescription((String) data.get("description"));
        rule.setAuthor((String) data.get("author"));
        rule.setDate(String.valueOf(data.get("date")));

        String level = (String) data.get("level");
        rule.setLevel(level != null ? level.toUpperCase() : "MEDIUM");

        // Extract Rule Code (e.g., D001 from D001_repeated_ssh_failures.yml)
        if (filename != null) {
            Matcher m = CODE_FROM_NAME_PATTERN.matcher(filename);
            if (m.find()) {
                rule.setRuleCode(m.group(1));
            }
        }
        if (rule.getRuleCode() == null && data.containsKey("rule_code")) {
            rule.setRuleCode((String) data.get("rule_code"));
        }

        // Tags and MITRE ATT&CK mappings
        Object tagsObj = data.get("tags");
        if (tagsObj instanceof List<?> tagList) {
            List<String> tags = new ArrayList<>();
            for (Object t : tagList) {
                if (t != null) {
                    String tag = t.toString().trim();
                    tags.add(tag);

                    // Check for technique: attack.t1059.001 -> T1059.001
                    Matcher techMatcher = TECHNIQUE_TAG_PATTERN.matcher(tag);
                    if (techMatcher.matches()) {
                        rule.setMitreTechniqueId(techMatcher.group(1).toUpperCase());
                    } else if (tag.startsWith("attack.") && !tag.contains(".")) {
                        rule.setMitreTactic(capitalize(tag.substring(7).replace('_', ' ')));
                    } else if (tag.startsWith("attack.") && tag.split("\\.").length == 2 && !tag.matches(".*t[0-9].*")) {
                        rule.setMitreTactic(capitalize(tag.split("\\.")[1].replace('_', ' ')));
                    }
                }
            }
            rule.setTags(tags);
        }

        // References
        Object refObj = data.get("references");
        if (refObj instanceof List<?> refList) {
            rule.setReferences(refList.stream().filter(Objects::nonNull).map(Object::toString).toList());
        }

        // False Positives
        Object fpObj = data.get("falsepositives");
        if (fpObj instanceof List<?> fpList) {
            rule.setFalsePositives(fpList.stream().filter(Objects::nonNull).map(Object::toString).toList());
        }

        // Logsource
        Object logsourceObj = data.get("logsource");
        if (logsourceObj instanceof Map<?, ?> logsourceMap) {
            rule.setLogsource((Map<String, Object>) logsourceMap);
        }

        // Detection Section
        Object detectionObj = data.get("detection");
        if (detectionObj instanceof Map<?, ?> detectionMap) {
            rule.setDetection((Map<String, Object>) detectionMap);
        }

        return rule;
    }

    private String capitalize(String text) {
        if (text == null || text.isEmpty()) return text;
        String[] parts = text.split(" ");
        StringBuilder sb = new StringBuilder();
        for (String p : parts) {
            if (!p.isEmpty()) {
                sb.append(Character.toUpperCase(p.charAt(0))).append(p.substring(1).toLowerCase()).append(" ");
            }
        }
        return sb.toString().trim();
    }
}
