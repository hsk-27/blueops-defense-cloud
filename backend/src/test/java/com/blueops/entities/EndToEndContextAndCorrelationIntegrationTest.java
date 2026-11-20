package com.blueops.entities;

import com.blueops.correlation.*;
import com.blueops.findings.FindingDto;
import com.blueops.incidents.IncidentDto;
import com.blueops.incidents.IncidentService;
import com.blueops.telemetry.NormalizedEvent;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.time.Instant;
import java.util.*;

import static org.junit.jupiter.api.Assertions.*;

class EndToEndContextAndCorrelationIntegrationTest {

    private M5TestStubs.StubEntityRepository entityRepository;
    private M5TestStubs.StubEntityObservationRepository observationRepository;
    private M5TestStubs.StubEntityRelationshipRepository relationshipRepository;
    private M5TestStubs.StubCorrelationRepository correlationRepository;
    private M5TestStubs.StubCorrelationRuleRepository ruleRepository;
    private M5TestStubs.StubCorrelationFindingRepository findingAssociationRepository;
    private M5TestStubs.StubCorrelationEntityRepository entityAssociationRepository;

    private EntityResolutionService resolutionService;
    private EntityExtractionService extractionService;
    private EntityService entityService;
    private CorrelationService correlationService;

    @BeforeEach
    void setUp() {
        entityRepository = new M5TestStubs.StubEntityRepository();
        observationRepository = new M5TestStubs.StubEntityObservationRepository();
        relationshipRepository = new M5TestStubs.StubEntityRelationshipRepository();
        correlationRepository = new M5TestStubs.StubCorrelationRepository();
        ruleRepository = new M5TestStubs.StubCorrelationRuleRepository();
        findingAssociationRepository = new M5TestStubs.StubCorrelationFindingRepository();
        entityAssociationRepository = new M5TestStubs.StubCorrelationEntityRepository();

        IncidentService incidentService = new IncidentService(null, null, null, null, null) {
            @Override
            public IncidentDto createIncident(com.blueops.incidents.IncidentCreateRequest request, String createdBy) {
                IncidentDto dto = new IncidentDto();
                dto.setId(999L);
                dto.setIncidentNumber("INC-20261120-999");
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

        ObjectMapper mapper = new ObjectMapper();
        resolutionService = new EntityResolutionService(entityRepository, observationRepository, relationshipRepository, mapper);
        extractionService = new EntityExtractionService(resolutionService);
        entityService = new EntityService(entityRepository, observationRepository, relationshipRepository, mapper);
        correlationService = new CorrelationService(correlationRepository, ruleRepository, findingAssociationRepository,
                entityAssociationRepository, entityRepository, incidentService);
    }

    @Test
    @DisplayName("Scenario A & G: Shared Host produces correlated multi-stage findings with explainable evidence")
    void testScenarioA_SharedHostAndExplanation() {
        NormalizedEvent event1 = new NormalizedEvent();
        event1.setId("evt-win-01");
        event1.setTimestamp(Instant.now().minus(Duration.ofMinutes(10)));
        event1.setHost(new NormalizedEvent.HostMetadata("h-1", "WIN-PROD-01", "192.168.1.50", "Windows", "11"));
        event1.setUser(new NormalizedEvent.UserMetadata("analyst", "u-1", "CORP"));
        event1.setProcess(new NormalizedEvent.ProcessMetadata(1234L, "powershell.exe", "C:\\Windows\\System32\\powershell.exe", "-enc aWV4...", null, null));

        extractionService.extractFromEvent(event1);

        assertTrue(entityRepository.existsByCanonicalId("host:win-prod-01"));
        assertTrue(entityRepository.existsByCanonicalId("user:corp\\analyst"));
        assertTrue(entityRepository.existsByCanonicalId("proc:win-prod-01:powershell.exe:1234"));

        FindingDto f1 = new FindingDto("FND-A1", "D009", "Parent Process Spawned Cmd", "MEDIUM",
                "EXECUTION", "T1059", "Command Interpreter", "WIN-PROD-01", "WIN-PROD-01",
                Instant.now().minus(Duration.ofMinutes(8)), "OPEN", "evt-win-01", Map.of());
        FindingDto f2 = new FindingDto("FND-A2", "D008", "Encoded PowerShell", "HIGH",
                "EXECUTION", "T1059.001", "PowerShell", "WIN-PROD-01", "WIN-PROD-01",
                Instant.now().minus(Duration.ofMinutes(5)), "OPEN", "evt-win-01", Map.of());

        extractionService.extractFromFinding(f1);
        extractionService.extractFromFinding(f2);

        List<CorrelationRecord> correlations = correlationService.evaluateAndPersist(List.of(f1, f2));

        assertEquals(1, correlations.size());
        CorrelationRecord corr = correlations.get(0);
        assertEquals("CORR-002", corr.getRuleId());
        assertEquals("host:win-prod-01", corr.getPrimaryEntityCanonicalId());
        assertNotNull(corr.getExplanation());
        assertTrue(corr.getExplanation().contains("Execution chain satisfied on WIN-PROD-01"));
    }

    @Test
    @DisplayName("Scenario B & C: Shared Identity and Temporal Attack Sequence")
    void testScenarioB_C_SharedIdentityAndTemporalSequence() {
        NormalizedEvent sshFail = new NormalizedEvent();
        sshFail.setId("evt-ssh-fail");
        sshFail.setTimestamp(Instant.now().minus(Duration.ofMinutes(20)));
        sshFail.setHost(new NormalizedEvent.HostMetadata("h-2", "LNX-GATEWAY", "10.0.0.1", "Linux", "Ubuntu"));
        sshFail.setUser(new NormalizedEvent.UserMetadata("root", "u-root", null));

        NormalizedEvent sshSuccess = new NormalizedEvent();
        sshSuccess.setId("evt-ssh-succ");
        sshSuccess.setTimestamp(Instant.now().minus(Duration.ofMinutes(5)));
        sshSuccess.setHost(new NormalizedEvent.HostMetadata("h-2", "LNX-GATEWAY", "10.0.0.1", "Linux", "Ubuntu"));
        sshSuccess.setUser(new NormalizedEvent.UserMetadata("root", "u-root", null));

        extractionService.extractFromEvent(sshFail);
        extractionService.extractFromEvent(sshSuccess);

        Optional<EntityRecord> rootUser = entityRepository.findByCanonicalId("user:root");
        assertTrue(rootUser.isPresent());
        assertEquals(2, rootUser.get().getObservationCount());

        FindingDto f1 = new FindingDto("FND-B1", "D001", "SSH Brute Force", "HIGH",
                "CREDENTIAL_ACCESS", "T1110", "Brute Force", "LNX-GATEWAY", "LNX-GATEWAY",
                Instant.now().minus(Duration.ofMinutes(15)), "OPEN", "evt-ssh-fail", Map.of("user.name", "root"));

        FindingDto f2 = new FindingDto("FND-B2", "D002", "SSH Login Success After Failures", "HIGH",
                "INITIAL_ACCESS", "T1078", "Valid Accounts", "LNX-GATEWAY", "LNX-GATEWAY",
                Instant.now().minus(Duration.ofMinutes(5)), "OPEN", "evt-ssh-succ", Map.of("user.name", "root"));

        extractionService.extractFromFinding(f1);
        extractionService.extractFromFinding(f2);

        List<CorrelationRecord> correlations = correlationService.evaluateAndPersist(List.of(f1, f2));
        assertEquals(1, correlations.size());
        assertEquals("CORR-001", correlations.get(0).getRuleId());
    }

    @Test
    @DisplayName("Scenario D & E: No False Association and Ambiguous Entity scoping")
    void testScenarioD_E_NoFalseAssociationAndAmbiguity() {
        NormalizedEvent e1 = new NormalizedEvent();
        e1.setId("e-host1");
        e1.setHost(new NormalizedEvent.HostMetadata("h-1", "HOST-ALPHA", "10.0.0.1", "Linux", "Debian"));
        e1.setProcess(new NormalizedEvent.ProcessMetadata(500L, "agent", "/usr/bin/agent", null, null, null));

        NormalizedEvent e2 = new NormalizedEvent();
        e2.setId("e-host2");
        e2.setHost(new NormalizedEvent.HostMetadata("h-2", "HOST-BETA", "10.0.0.2", "Linux", "Debian"));
        e2.setProcess(new NormalizedEvent.ProcessMetadata(500L, "agent", "/usr/bin/agent", null, null, null));

        extractionService.extractFromEvent(e1);
        extractionService.extractFromEvent(e2);

        assertTrue(entityRepository.existsByCanonicalId("host:host-alpha"));
        assertTrue(entityRepository.existsByCanonicalId("host:host-beta"));
        assertNotEquals(entityRepository.findByCanonicalId("host:host-alpha").get().getId(),
                entityRepository.findByCanonicalId("host:host-beta").get().getId());

        assertTrue(entityRepository.existsByCanonicalId("proc:host-alpha:agent:500"));
        assertTrue(entityRepository.existsByCanonicalId("proc:host-beta:agent:500"));
        assertNotEquals(entityRepository.findByCanonicalId("proc:host-alpha:agent:500").get().getId(),
                entityRepository.findByCanonicalId("proc:host-beta:agent:500").get().getId(),
                "Processes on different hosts must not falsely collide despite having identical PID and name");
    }

    @Test
    @DisplayName("Scenario F: Duplicate Telemetry Ingestion increments observation counts idempotently")
    void testScenarioF_DuplicateTelemetryIdempotency() {
        NormalizedEvent event = new NormalizedEvent();
        event.setId("dup-evt");
        event.setHost(new NormalizedEvent.HostMetadata("h-dup", "WIN-IDEMPOTENT", "192.168.1.99", "Windows", "10"));

        extractionService.extractFromEvent(event);
        extractionService.extractFromEvent(event);
        extractionService.extractFromEvent(event);

        assertEquals(1, entityRepository.count(), "Duplicate events must not create duplicate entities");
        EntityRecord host = entityRepository.findByCanonicalId("host:win-idempotent").get();
        assertEquals(3, host.getObservationCount(), "Observation count must increment accurately");
    }

    @Test
    @DisplayName("Scenario H: Incident Context Promotion preserves correlation linkage")
    void testScenarioH_IncidentContextPromotion() {
        FindingDto f1 = new FindingDto("FND-H1", "D008", "PowerShell", "HIGH", "EXEC", "T1059", "PS", "WIN-01", "WIN-01", Instant.now(), "OPEN", "d1", Map.of());
        FindingDto f2 = new FindingDto("FND-H2", "D014", "Outbound Port 4444", "HIGH", "C2", "T1071", "Net", "WIN-01", "WIN-01", Instant.now(), "OPEN", "d2", Map.of());

        List<CorrelationRecord> records = correlationService.evaluateAndPersist(List.of(f1, f2));
        assertFalse(records.isEmpty());
        CorrelationRecord corr = records.get(0);

        IncidentDto incident = correlationService.promoteToIncident(corr.getId(), "lead.analyst");

        assertNotNull(incident);
        assertEquals(999L, incident.getId());
        assertEquals(CorrelationStatus.PROMOTED_TO_INCIDENT, corr.getStatus());
        assertEquals(999L, corr.getIncidentId());
    }

    @Test
    @DisplayName("Scenario I: Failure Handling isolates malformed and null events safely")
    void testScenarioI_DefensiveFailureIsolation() {
        assertDoesNotThrow(() -> extractionService.extractFromEvent(null));
        assertDoesNotThrow(() -> extractionService.extractFromFinding(null));

        NormalizedEvent brokenEvent = new NormalizedEvent();
        brokenEvent.setHost(new NormalizedEvent.HostMetadata(null, null, null, null, null));
        assertDoesNotThrow(() -> extractionService.extractFromEvent(brokenEvent));
    }
}
