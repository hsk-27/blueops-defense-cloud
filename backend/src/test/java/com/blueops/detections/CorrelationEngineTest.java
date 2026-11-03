package com.blueops.detections;

import com.blueops.detections.correlation.CorrelationEngine;
import com.blueops.findings.FindingDto;
import com.blueops.incidents.IncidentSeverity;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class CorrelationEngineTest {

    private CorrelationEngine correlationEngine;

    @BeforeEach
    void setUp() {
        correlationEngine = new CorrelationEngine();
    }

    @Test
    void testC001LinuxCompromiseCorrelation() {
        FindingDto f1 = new FindingDto("F1", "D001", "SSH Failures", "MEDIUM", "Credential Access", "T1110.001", "Password Guessing", "LNX-01", "LAB-LNX-01", Instant.now().minusSeconds(100), "UNASSIGNED", "DOC1", null);
        FindingDto f2 = new FindingDto("F2", "D002", "SSH Success", "HIGH", "Credential Access", "T1110", "Brute Force", "LNX-01", "LAB-LNX-01", Instant.now().minusSeconds(50), "UNASSIGNED", "DOC2", null);

        List<CorrelationEngine.CorrelatedScenario> scenarios = correlationEngine.evaluateFindings(List.of(f1, f2));

        assertFalse(scenarios.isEmpty());
        CorrelationEngine.CorrelatedScenario s = scenarios.get(0);
        assertEquals("C001", s.scenarioCode());
        assertEquals(IncidentSeverity.CRITICAL, s.severity());
        assertEquals("LNX-01", s.assetId());
    }

    @Test
    void testC002WindowsExecutionChain() {
        FindingDto f1 = new FindingDto("F1", "D009", "Unusual Parent Child", "CRITICAL", "Execution", "T1059", "Command Interpreter", "WIN-01", "LAB-WIN-01", Instant.now().minusSeconds(60), "UNASSIGNED", "DOC1", null);
        FindingDto f2 = new FindingDto("F2", "D008", "Suspicious PowerShell", "HIGH", "Execution", "T1059.001", "PowerShell", "WIN-01", "LAB-WIN-01", Instant.now().minusSeconds(40), "UNASSIGNED", "DOC2", null);

        List<CorrelationEngine.CorrelatedScenario> scenarios = correlationEngine.evaluateFindings(List.of(f1, f2));

        assertFalse(scenarios.isEmpty());
        assertEquals("C002", scenarios.get(0).scenarioCode());
    }

    @Test
    void testC003ThreatIntelActivityCorrelation() {
        FindingDto f1 = new FindingDto("F1", "D015", "Known IOC Communication", "HIGH", "Command and Control", "T1071", "C2 Channel", "WIN-01", "LAB-WIN-01", Instant.now().minusSeconds(30), "UNASSIGNED", "DOC1", null);
        FindingDto f2 = new FindingDto("F2", "D014", "Unusual Outbound Network", "MEDIUM", "Command and Control", "T1071.001", "Web Protocols", "WIN-01", "LAB-WIN-01", Instant.now().minusSeconds(20), "UNASSIGNED", "DOC2", null);

        List<CorrelationEngine.CorrelatedScenario> scenarios = correlationEngine.evaluateFindings(List.of(f1, f2));

        assertFalse(scenarios.isEmpty());
        CorrelationEngine.CorrelatedScenario s = scenarios.get(0);
        assertEquals("C003", s.scenarioCode());
        assertEquals(IncidentSeverity.HIGH, s.severity());
        assertEquals("WIN-01", s.assetId());
    }

    @Test
    void testC004PrivilegeManipulationCorrelation() {
        FindingDto f1 = new FindingDto("F1", "D005", "Local Account Creation", "HIGH", "Persistence", "T1136.001", "Local Account", "LNX-01", "LAB-LNX-01", Instant.now().minusSeconds(80), "UNASSIGNED", "DOC1", null);
        FindingDto f2 = new FindingDto("F2", "D007", "System Service Creation", "MEDIUM", "Persistence", "T1543.002", "Systemd Service", "LNX-01", "LAB-LNX-01", Instant.now().minusSeconds(40), "UNASSIGNED", "DOC2", null);

        List<CorrelationEngine.CorrelatedScenario> scenarios = correlationEngine.evaluateFindings(List.of(f1, f2));

        assertFalse(scenarios.isEmpty());
        CorrelationEngine.CorrelatedScenario s = scenarios.get(0);
        assertEquals("C004", s.scenarioCode());
        assertEquals(IncidentSeverity.HIGH, s.severity());
        assertEquals("LNX-01", s.assetId());
    }
}
