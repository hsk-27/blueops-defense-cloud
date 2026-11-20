package com.blueops.response;

import com.blueops.audit.AuditLog;
import com.blueops.audit.AuditLogRepository;
import com.blueops.audit.AuditService;
import com.blueops.entities.*;
import com.blueops.findings.FindingDto;
import com.blueops.incidents.*;
import com.blueops.telemetry.NormalizedEvent;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.time.Instant;
import java.util.*;

import static org.junit.jupiter.api.Assertions.*;

class EndToEndSoarOrchestrationTest {

    private M6TestStubs.StubCatalogRepository catalogRepository;
    private M6TestStubs.StubTargetRepository targetRepository;
    private M6TestStubs.StubProposalRepository proposalRepository;
    private M6TestStubs.StubVerificationRepository verificationRepository;

    private M5TestStubs.StubEntityRepository entityRepository;
    private M5TestStubs.StubEntityObservationRepository observationRepository;
    private M5TestStubs.StubEntityRelationshipRepository relationshipRepository;

    private ResponsePolicyEngine policyEngine;
    private ResponseVerificationEngine verificationEngine;
    private SimulationResponseAdapter simulationAdapter;
    private ResponseSoarOrchestrator orchestrator;

    private EntityResolutionService resolutionService;
    private EntityExtractionService extractionService;

    private List<AuditLog> auditTrail;
    private AuditService auditService;

    @BeforeEach
    void setUp() {
        catalogRepository = new M6TestStubs.StubCatalogRepository();
        targetRepository = new M6TestStubs.StubTargetRepository();
        proposalRepository = new M6TestStubs.StubProposalRepository();
        verificationRepository = new M6TestStubs.StubVerificationRepository();

        entityRepository = new M5TestStubs.StubEntityRepository();
        observationRepository = new M5TestStubs.StubEntityObservationRepository();
        relationshipRepository = new M5TestStubs.StubEntityRelationshipRepository();

        ObjectMapper mapper = new ObjectMapper();
        resolutionService = new EntityResolutionService(entityRepository, observationRepository, relationshipRepository, mapper);
        extractionService = new EntityExtractionService(resolutionService);

        // Audit spy
        auditTrail = new ArrayList<>();
        AuditLogRepository auditRepo = new AuditLogRepository() {
            @Override public <S extends AuditLog> S save(S entity) { auditTrail.add(entity); return entity; }
            @Override public <S extends AuditLog> List<S> saveAll(Iterable<S> entities) { return List.of(); }
            @Override public Optional<AuditLog> findById(Long aLong) { return Optional.empty(); }
            @Override public boolean existsById(Long aLong) { return false; }
            @Override public List<AuditLog> findAll() { return auditTrail; }
            @Override public List<AuditLog> findAllById(Iterable<Long> longs) { return List.of(); }
            @Override public long count() { return auditTrail.size(); }
            @Override public void deleteById(Long aLong) {}
            @Override public void delete(AuditLog entity) {}
            @Override public void deleteAllById(Iterable<? extends Long> longs) {}
            @Override public void deleteAll(Iterable<? extends AuditLog> entities) {}
            @Override public void deleteAll() { auditTrail.clear(); }
            @Override public List<AuditLog> findTop100ByOrderByTimestampDesc() { return auditTrail; }
            @Override public org.springframework.data.domain.Page<AuditLog> findAllByOrderByTimestampDesc(org.springframework.data.domain.Pageable pageable) { return org.springframework.data.domain.Page.empty(); }
            @Override public void flush() {}
            @Override public <S extends AuditLog> S saveAndFlush(S entity) { return save(entity); }
            @Override public <S extends AuditLog> List<S> saveAllAndFlush(Iterable<S> entities) { return List.of(); }
            @Override public void deleteAllInBatch(Iterable<AuditLog> entities) {}
            @Override public void deleteAllByIdInBatch(Iterable<Long> longs) {}
            @Override public void deleteAllInBatch() {}
            @Override public AuditLog getOne(Long aLong) { return null; }
            @Override public AuditLog getById(Long aLong) { return null; }
            @Override public AuditLog getReferenceById(Long aLong) { return null; }
            @Override public <S extends AuditLog> Optional<S> findOne(org.springframework.data.domain.Example<S> example) { return Optional.empty(); }
            @Override public <S extends AuditLog> List<S> findAll(org.springframework.data.domain.Example<S> example) { return List.of(); }
            @Override public <S extends AuditLog> List<S> findAll(org.springframework.data.domain.Example<S> example, org.springframework.data.domain.Sort sort) { return List.of(); }
            @Override public <S extends AuditLog> org.springframework.data.domain.Page<S> findAll(org.springframework.data.domain.Example<S> example, org.springframework.data.domain.Pageable pageable) { return org.springframework.data.domain.Page.empty(); }
            @Override public <S extends AuditLog> long count(org.springframework.data.domain.Example<S> example) { return 0; }
            @Override public <S extends AuditLog> boolean exists(org.springframework.data.domain.Example<S> example) { return false; }
            @Override public <S extends AuditLog, R> R findBy(org.springframework.data.domain.Example<S> example, java.util.function.Function<org.springframework.data.repository.query.FluentQuery.FetchableFluentQuery<S>, R> queryFunction) { return null; }
            @Override public List<AuditLog> findAll(org.springframework.data.domain.Sort sort) { return auditTrail; }
            @Override public org.springframework.data.domain.Page<AuditLog> findAll(org.springframework.data.domain.Pageable pageable) { return org.springframework.data.domain.Page.empty(); }
        };
        auditService = new AuditService(auditRepo);

        // Seed Actions
        ResponseActionDefinition actBlock = new ResponseActionDefinition();
        actBlock.setActionCode("ACT-001");
        actBlock.setName("Block Lab Source IP");
        actBlock.setDescription("Applies drop rules");
        actBlock.setCategory("DEFENSIVE_CONTAINMENT");
        actBlock.setTargetType("IP");
        actBlock.setRiskLevel(ResponseRiskLevel.MODERATE);
        actBlock.setRequiresApproval(true);
        catalogRepository.save(actBlock);

        ResponseActionDefinition actIsolate = new ResponseActionDefinition();
        actIsolate.setActionCode("ACT-003");
        actIsolate.setName("Isolate Compromised Host Endpoint");
        actIsolate.setDescription("Network quarantine");
        actIsolate.setCategory("DEFENSIVE_CONTAINMENT");
        actIsolate.setTargetType("ASSET");
        actIsolate.setRiskLevel(ResponseRiskLevel.CRITICAL);
        actIsolate.setRequiresApproval(true);
        catalogRepository.save(actIsolate);

        // Seed Targets
        ResponseTargetRecord tgtIp = new ResponseTargetRecord();
        tgtIp.setTargetId("TGT-IP-101");
        tgtIp.setTargetType("IP");
        tgtIp.setIdentifier("198.51.100.24");
        tgtIp.setDisplayName("Malicious External C2 Node");
        targetRepository.save(tgtIp);

        ResponseTargetRecord tgtHost = new ResponseTargetRecord();
        tgtHost.setTargetId("TGT-HST-101");
        tgtHost.setTargetType("HOST");
        tgtHost.setIdentifier("win-prod-01");
        tgtHost.setDisplayName("Production Workstation");
        targetRepository.save(tgtHost);

        policyEngine = new ResponsePolicyEngine(targetRepository);
        verificationEngine = new ResponseVerificationEngine(verificationRepository);
        simulationAdapter = new SimulationResponseAdapter();

        orchestrator = new ResponseSoarOrchestrator(
                proposalRepository,
                catalogRepository,
                targetRepository,
                verificationRepository,
                null,
                policyEngine,
                verificationEngine,
                List.of(simulationAdapter),
                auditService,
                mapper
        );
    }

    @Test
    @DisplayName("End-to-End M3->M4->M5->M6 Synthetic Pipeline Scenario")
    void testFullOperationalLifecycle_DetectionToVerifiedResponse() {
        // Step 1: Telemetry Ingest & Entity Extraction (M3/M5)
        NormalizedEvent event = new NormalizedEvent();
        event.setId("evt-c2-01");
        event.setTimestamp(Instant.now());
        event.setHost(new NormalizedEvent.HostMetadata("h-1", "WIN-PROD-01", "192.168.1.50", "Windows", "11"));
        event.setUser(new NormalizedEvent.UserMetadata("analyst", "u-1", "CORP"));
        event.setDestination(new NormalizedEvent.NetworkEndpoint("198.51.100.24", 443, null));

        List<EntityRecord> entities = extractionService.extractFromEvent(event);
        assertTrue(entities.stream().anyMatch(e -> e.getCanonicalId().equals("host:win-prod-01")));
        assertTrue(entities.stream().anyMatch(e -> e.getCanonicalId().equals("ip:198.51.100.24")));

        // Step 2: Detection Finding Generated (M3)
        FindingDto finding = new FindingDto(
                "FND-C2-01", "D010", "Beaconing to Known Malicious IP", "HIGH",
                "COMMAND_AND_CONTROL", "T1071", "Application Layer Protocol",
                "WIN-PROD-01", "198.51.100.24", Instant.now(), "OPEN", "evt-c2-01", Map.of()
        );
        extractionService.extractFromFinding(finding);

        // Step 3: Response Policy Preview & Proposal Generation (M6)
        CreateProposalRequestDto proposalReq = new CreateProposalRequestDto();
        proposalReq.setActionCode("ACT-001");
        proposalReq.setTargetIdentifier("198.51.100.24");
        proposalReq.setTargetCanonicalId("ip:198.51.100.24");
        proposalReq.setFindingId(finding.getFindingId());
        proposalReq.setExecutionMode(ResponseExecutionMode.SIMULATION);
        proposalReq.setParameters(Map.of("firewallZone", "PERIMETER_DROP"));

        PolicyEvaluationResultDto preview = orchestrator.evaluatePolicyPreview(proposalReq, "analyst-alice");
        assertEquals(ResponsePolicyOutcome.REQUIRE_APPROVAL, preview.getOutcome());
        assertEquals(ResponseRiskLevel.MODERATE, preview.getRiskLevel());
        assertTrue(preview.isRequiresApproval());

        ResponseProposalDto proposal = orchestrator.createProposal(proposalReq, "analyst-alice");
        assertEquals("PENDING_APPROVAL", proposal.getStatus());
        assertEquals("PROP-", proposal.getProposalUuid().substring(0, 5));

        // Step 4: Multi-Stage Approval by Senior Analyst (M6.7)
        ApproveProposalRequestDto approveReq = new ApproveProposalRequestDto("Approved automated lab firewall block", false);
        ResponseProposalDto approved = orchestrator.approveProposal(proposal.getId(), approveReq, "lead-bob");
        assertEquals("APPROVED", approved.getStatus());
        assertEquals("lead-bob", approved.getApprover());

        // Step 5: Bounded Adapter Execution & Independent Verification (M6.8, M6.10)
        ResponseProposalDto executed = orchestrator.executeProposal(approved.getId(), "lead-bob");
        assertEquals("VERIFIED", executed.getStatus());
        assertNotNull(executed.getVerification());
        assertEquals("VERIFIED", executed.getVerification().getStatus());
        assertTrue(executed.getVerification().isSimulation());
        assertTrue(executed.getVerification().getObservedOutcome().contains("Simulated lab firewall table query confirmed"));

        // Step 6: Validate Audit Trail Integrity (M6.11)
        assertTrue(auditTrail.stream().anyMatch(a -> a.getAction().equals("RESPONSE_PROPOSAL_CREATED")));
        assertTrue(auditTrail.stream().anyMatch(a -> a.getAction().equals("RESPONSE_PROPOSAL_APPROVED")));
        assertTrue(auditTrail.stream().anyMatch(a -> a.getAction().equals("RESPONSE_ACTION_EXECUTED")));

        AuditLog execAudit = auditTrail.stream().filter(a -> a.getAction().equals("RESPONSE_ACTION_EXECUTED")).findFirst().orElseThrow();
        assertEquals("lead-bob", execAudit.getActor());
        assertTrue(execAudit.getDetails().contains("SUCCESS"));
    }
}
