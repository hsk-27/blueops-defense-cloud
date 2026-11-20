package com.blueops.detections.sigma;

import com.blueops.findings.FindingDto;
import com.blueops.telemetry.NormalizedEvent;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class SigmaDetectionEvaluatorTest {

    private SigmaRuleRegistry registry;
    private SigmaDetectionEvaluator evaluator;

    @BeforeEach
    void setUp() {
        SigmaRuleParser parser = new SigmaRuleParser();
        registry = new SigmaRuleRegistry(parser, "");
        registry.reloadRules();

        SigmaFieldMatcher matcher = new SigmaFieldMatcher();
        SigmaConditionEvaluator conditionEvaluator = new SigmaConditionEvaluator();
        evaluator = new SigmaDetectionEvaluator(registry, matcher, conditionEvaluator);
    }

    @Test
    @DisplayName("Should dynamically detect suspicious PowerShell encoded execution via D008 Sigma rule")
    void testDynamicD008PowerShellDetection() {
        NormalizedEvent event = new NormalizedEvent();
        event.setId("evt-ps-101");
        event.setHost(new NormalizedEvent.HostMetadata("WIN-ASSET-001", "WIN-SRV-2022", "192.168.1.105", "Windows", "10.0"));
        event.setEvent(new NormalizedEvent.EventMetadata(
                "evt-ps-101", "Microsoft-Windows-Sysmon", "windows.process_creation",
                List.of("process"), List.of("start"), "process_started", 3, null
        ));
        event.setProcess(new NormalizedEvent.ProcessMetadata(
                4012L, "powershell.exe", "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                "powershell.exe -ExecutionPolicy Bypass -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA...",
                "sha256hash", null
        ));

        List<FindingDto> findings = evaluator.evaluate(event, "WIN-ASSET-001", "WIN-SRV-2022");

        assertFalse(findings.isEmpty(), "Dynamic Sigma engine should produce finding for D008");
        FindingDto d008Finding = findings.stream()
                .filter(f -> "D008".equals(f.getRuleId()))
                .findFirst()
                .orElse(null);

        assertNotNull(d008Finding, "Finding for D008 must exist");
        assertEquals("HIGH", d008Finding.getRuleSeverity());
        assertEquals("T1059.001", d008Finding.getMitreTechniqueId());
        assertEquals("Execution", d008Finding.getMitreTactic());
        assertEquals("WIN-ASSET-001", d008Finding.getAssetId());
    }

    @Test
    @DisplayName("Should dynamically detect Office spawning shell via D009 Sigma rule")
    void testDynamicD009ParentChildDetection() {
        NormalizedEvent event = new NormalizedEvent();
        event.setId("evt-parent-child-102");
        event.setHost(new NormalizedEvent.HostMetadata("WIN-ASSET-001", "WIN-SRV-2022", "192.168.1.105", "Windows", "10.0"));
        event.setEvent(new NormalizedEvent.EventMetadata(
                "evt-parent-child-102", "Microsoft-Windows-Sysmon", "windows.process_creation",
                List.of("process"), List.of("start"), "process_started", 4, null
        ));
        NormalizedEvent.ProcessParent parent = new NormalizedEvent.ProcessParent(
                2104L, "winword.exe", "C:\\Program Files\\Microsoft Office\\root\\Office16\\winword.exe",
                "winword.exe /n C:\\Users\\victim\\invoice.docm"
        );
        event.setProcess(new NormalizedEvent.ProcessMetadata(
                5512L, "cmd.exe", "C:\\Windows\\System32\\cmd.exe",
                "cmd.exe /c powershell.exe -w hidden -enc ...",
                "sha256hash", parent
        ));

        List<FindingDto> findings = evaluator.evaluate(event, "WIN-ASSET-001", "WIN-SRV-2022");

        assertFalse(findings.isEmpty());
        assertTrue(findings.stream().anyMatch(f -> "D009".equals(f.getRuleId())));
    }
}
