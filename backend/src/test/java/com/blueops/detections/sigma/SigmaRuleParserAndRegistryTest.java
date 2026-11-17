package com.blueops.detections.sigma;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;

class SigmaRuleParserAndRegistryTest {

    private final SigmaRuleParser parser = new SigmaRuleParser();

    @Test
    @DisplayName("Should successfully parse a raw Sigma YAML string into strongly typed SigmaRuleDefinition")
    void testParseRawYaml() {
        String yaml = """
            title: Suspicious PowerShell Encoded Execution
            id: 5f1b1e90-0008-4e89-9a08-000000000008
            status: test
            description: Detects encoded PowerShell execution flags.
            references:
                - https://attack.mitre.org/techniques/T1059/001/
            author: BlueOps Detection Engineering
            date: 2026-11-01
            tags:
                - attack.execution
                - attack.t1059.001
            logsource:
                category: process_creation
                product: windows
                service: sysmon
            detection:
                selection:
                    CommandLine|contains:
                        - ' -enc '
                        - ' -EncodedCommand '
                condition: selection
            level: high
            """;

        SigmaRuleDefinition rule = parser.parse(yaml, "D008_suspicious_powershell.yml");

        assertNotNull(rule);
        assertEquals("D008", rule.getRuleCode());
        assertEquals("Suspicious PowerShell Encoded Execution", rule.getTitle());
        assertEquals("HIGH", rule.getLevel());
        assertEquals("T1059.001", rule.getMitreTechniqueId());
        assertEquals("Execution", rule.getMitreTactic());
        assertEquals("windows", rule.getLogsource().get("product"));
        assertNotNull(rule.getDetection());
    }

    @Test
    @DisplayName("Should load and register all 18 real Sigma YAML rule files from project storage")
    void testRegistryLoadsAllRealRules() {
        SigmaRuleRegistry registry = new SigmaRuleRegistry(parser, "");
        int loaded = registry.reloadRules();

        assertTrue(loaded >= 18, "Registry should load at least 18 Sigma rules. Actual: " + loaded);

        // Verify specific rules
        Optional<SigmaRuleDefinition> d001 = registry.getRuleByCode("D001");
        assertTrue(d001.isPresent(), "D001 should be loaded");
        assertEquals("Repeated SSH Authentication Failures", d001.get().getTitle());
        assertEquals("T1110.001", d001.get().getMitreTechniqueId());

        Optional<SigmaRuleDefinition> d008 = registry.getRuleByCode("D008");
        assertTrue(d008.isPresent(), "D008 should be loaded");
        assertEquals("Suspicious PowerShell Execution", d008.get().getTitle());
        assertEquals("T1059.001", d008.get().getMitreTechniqueId());

        Optional<SigmaRuleDefinition> d011 = registry.getRuleByCode("D011");
        assertTrue(d011.isPresent(), "D011 should be loaded");
        assertTrue(d011.get().getTitle().contains("LSASS"));

        Optional<SigmaRuleDefinition> d015 = registry.getRuleByCode("D015");
        assertTrue(d015.isPresent(), "D015 should be loaded");
        assertTrue(d015.get().getTitle().contains("Threat Intelligence"));

        // Verify logsource filtering
        List<SigmaRuleDefinition> windowsRules = registry.getRulesByLogSourceProduct("windows");
        assertFalse(windowsRules.isEmpty());
        assertTrue(windowsRules.stream().anyMatch(r -> "D008".equals(r.getRuleCode())));

        List<SigmaRuleDefinition> linuxRules = registry.getRulesByLogSourceProduct("linux");
        assertFalse(linuxRules.isEmpty());
        assertTrue(linuxRules.stream().anyMatch(r -> "D001".equals(r.getRuleCode())));
    }
}
