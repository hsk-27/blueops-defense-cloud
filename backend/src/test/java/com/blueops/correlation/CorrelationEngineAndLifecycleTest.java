package com.blueops.correlation;

import com.blueops.entities.EntityType;
import com.blueops.entities.M5TestStubs;
import com.blueops.findings.FindingDto;
import com.blueops.incidents.IncidentDto;
import com.blueops.incidents.IncidentService;
import com.blueops.incidents.IncidentSeverity;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.time.Instant;
import java.util.*;

import static org.junit.jupiter.api.Assertions.*;

class CorrelationEngineAndLifecycleTest {

    private M5TestStubs.StubCorrelationRepository correlationRepository;
    private M5TestStubs.StubCorrelationRuleRepository ruleRepository;
    private M5TestStubs.StubCorrelationFindingRepository findingAssociationRepository;
    private M5TestStubs.StubCorrelationEntityRepository entityAssociationRepository;
    private M5TestStubs.StubEntityRepository entityRepository;
    private IncidentService incidentService;
    private CorrelationService correlationService;

    @BeforeEach
    void setUp() {
        correlationRepository = new M5TestStubs.StubCorrelationRepository();
        ruleRepository = new M5TestStubs.StubCorrelationRuleRepository();
        findingAssociationRepository = new M5TestStubs.StubCorrelationFindingRepository();
        entityAssociationRepository = new M5TestStubs.StubCorrelationEntityRepository();
        entityRepository = new M5TestStubs.StubEntityRepository();

        // Anonymous mock/stub for IncidentService to avoid ByteBuddy agent loading
        incidentService = new IncidentService(null, null, null, null, null) {
            @Override
            public IncidentDto createIncident(com.blueops.incidents.IncidentCreateRequest request, String createdBy) {
                IncidentDto dto = new IncidentDto();
                dto.setId(55L);
                dto.setIncidentNumber("INC-20261120-055");
                dto.setTitle(request.getTitle());
                dto.setDescription(request.getDescription());
                dto.setSeverity(request.getSeverity() != null ? request.getSeverity().name() : "HIGH");
                dto.setPriority("P1_CRITICAL");
                dto.setStatus("NEW");
                dto.setCreatedBy(createdBy);
                dto.setCreatedAt(Instant.now());
                dto.setUpdatedAt(Instant.now());
                return dto;
            }
        };

        correlationService = new CorrelationService(
                correlationRepository,
                ruleRepository,
                findingAssociationRepository,
                entityAssociationRepository,
                entityRepository,
                incidentService
        );
    }

    @Test
    @DisplayName("CORR-001: Linux Compromise correlates brute force followed by privilege execution")
    void testLinuxCompromiseCorrelation() {
        Instant now = Instant.now();
        FindingDto f1 = new FindingDto("FND-001", "D001", "SSH Brute Force", "HIGH",
                "CREDENTIAL_ACCESS", "T1110", "Brute Force", "SRV-LNX-01", "SRV-LNX-01",
                now.minus(Duration.ofMinutes(15)), "OPEN", "doc1", Map.of());

        FindingDto f2 = new FindingDto("FND-002", "D004", "Privileged Execution (sudo bash)", "CRITICAL",
                "PRIVILEGE_ESCALATION", "T1548", "Abuse Elevation", "SRV-LNX-01", "SRV-LNX-01",
                now, "OPEN", "doc2", Map.of());

        List<CorrelationRecord> correlated = correlationService.evaluateAndPersist(List.of(f1, f2));

        assertEquals(1, correlated.size());
        CorrelationRecord record = correlated.get(0);
        assertEquals("CORR-001", record.getRuleId());
        assertEquals(IncidentSeverity.CRITICAL, record.getSeverity());
        assertEquals("host:srv-lnx-01", record.getPrimaryEntityCanonicalId());
        assertTrue(record.getExplanation().contains("Sequence satisfied on SRV-LNX-01"));
        assertEquals(2, findingAssociationRepository.count());
    }

    @Test
    @DisplayName("CORR-002: Windows Execution Chain correlates parent-child and encoded PowerShell")
    void testWindowsExecutionChainCorrelation() {
        Instant now = Instant.now();
        FindingDto f1 = new FindingDto("FND-101", "D009", "Unusual Parent Process Spawned Cmd", "MEDIUM",
                "EXECUTION", "T1059", "Command Interpreter", "WIN-WORKSTATION-01", "WIN-WORKSTATION-01",
                now.minus(Duration.ofMinutes(5)), "OPEN", "doc101", Map.of());

        FindingDto f2 = new FindingDto("FND-102", "D008", "Encoded PowerShell Execution", "HIGH",
                "EXECUTION", "T1059.001", "PowerShell", "WIN-WORKSTATION-01", "WIN-WORKSTATION-01",
                now, "OPEN", "doc102", Map.of());

        List<CorrelationRecord> correlated = correlationService.evaluateAndPersist(List.of(f1, f2));

        assertEquals(1, correlated.size());
        CorrelationRecord record = correlated.get(0);
        assertEquals("CORR-002", record.getRuleId());
        assertEquals("host:win-workstation-01", record.getPrimaryEntityCanonicalId());
    }

    @Test
    @DisplayName("CORR-005: Cross-Host Malware Hash Distribution correlates identical hashes across distinct hosts")
    void testCrossHostMalwareHashDistribution() {
        Instant now = Instant.now();
        String sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

        FindingDto f1 = new FindingDto("FND-201", "D011", "LSASS Dumping", "CRITICAL",
                "CREDENTIAL_ACCESS", "T1003", "OS Credential Dumping", "HOST-FINANCE-01", "HOST-FINANCE-01",
                now.minus(Duration.ofMinutes(10)), "OPEN", "doc201", Map.of("file.hash.sha256", sha256));

        FindingDto f2 = new FindingDto("FND-202", "D008", "PowerShell Download", "HIGH",
                "EXECUTION", "T1059", "PowerShell", "HOST-HR-02", "HOST-HR-02",
                now, "OPEN", "doc202", Map.of("file.hash.sha256", sha256));

        List<CorrelationRecord> correlated = correlationService.evaluateAndPersist(List.of(f1, f2));

        assertEquals(1, correlated.size());
        CorrelationRecord record = correlated.get(0);
        assertEquals("CORR-005", record.getRuleId());
        assertEquals("hash:sha256:" + sha256, record.getPrimaryEntityCanonicalId());
        assertEquals(EntityType.HASH, record.getPrimaryEntityType());
        assertTrue(record.getExplanation().contains("Lateral Spread Indicator"));
    }

    @Test
    @DisplayName("Temporal window rejection: Findings separated by more than 60 minutes are not correlated")
    void testTemporalWindowRejection() {
        Instant now = Instant.now();
        FindingDto f1 = new FindingDto("FND-301", "D001", "SSH Brute Force", "HIGH",
                "CREDENTIAL_ACCESS", "T1110", "Brute Force", "SRV-LNX-01", "SRV-LNX-01",
                now.minus(Duration.ofMinutes(120)), "OPEN", "doc301", Map.of());

        FindingDto f2 = new FindingDto("FND-302", "D004", "Privileged Execution", "CRITICAL",
                "PRIVILEGE_ESCALATION", "T1548", "Abuse Elevation", "SRV-LNX-01", "SRV-LNX-01",
                now, "OPEN", "doc302", Map.of());

        List<CorrelationRecord> correlated = correlationService.evaluateAndPersist(List.of(f1, f2));
        assertTrue(correlated.isEmpty(), "Findings outside 60-minute window must not be correlated");
    }

    @Test
    @DisplayName("Promotion to Incident: Generates incident and links correlation record")
    void testPromoteToIncident() {
        Instant now = Instant.now();
        FindingDto f1 = new FindingDto("FND-401", "D008", "PowerShell", "HIGH",
                "EXECUTION", "T1059", "PowerShell", "WIN-01", "WIN-01", now, "OPEN", "doc", Map.of());
        FindingDto f2 = new FindingDto("FND-402", "D014", "Outbound Port 4444", "HIGH",
                "COMMAND_AND_CONTROL", "T1071", "Application Layer Protocol", "WIN-01", "WIN-01", now, "OPEN", "doc", Map.of());

        List<CorrelationRecord> records = correlationService.evaluateAndPersist(List.of(f1, f2));
        assertFalse(records.isEmpty());
        CorrelationRecord record = records.get(0);

        IncidentDto created = correlationService.promoteToIncident(record.getId(), "secops.lead");

        assertNotNull(created);
        assertEquals(55L, created.getId());
        assertEquals(CorrelationStatus.PROMOTED_TO_INCIDENT, record.getStatus());
        assertEquals(55L, record.getIncidentId());
    }
}
