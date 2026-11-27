package com.blueops.response;

import com.blueops.common.exceptions.InvalidActionException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class ResponsePolicyAndLifecycleSecurityTest {

    private M6TestStubs.StubCatalogRepository catalogRepository;
    private M6TestStubs.StubTargetRepository targetRepository;
    private M6TestStubs.StubProposalRepository proposalRepository;
    private M6TestStubs.StubVerificationRepository verificationRepository;

    private ResponsePolicyEngine policyEngine;
    private ResponseVerificationEngine verificationEngine;
    private SimulationResponseAdapter simulationAdapter;
    private ResponseSoarOrchestrator orchestrator;

    private ResponseActionDefinition blockIpAction;
    private ResponseActionDefinition disableUserAction;
    private ResponseActionDefinition isolateHostAction;
    private ResponseActionDefinition evidenceAction;

    @BeforeEach
    void setUp() {
        catalogRepository = new M6TestStubs.StubCatalogRepository();
        targetRepository = new M6TestStubs.StubTargetRepository();
        proposalRepository = new M6TestStubs.StubProposalRepository();
        verificationRepository = new M6TestStubs.StubVerificationRepository();

        // Seed Action Catalog
        blockIpAction = new ResponseActionDefinition();
        blockIpAction.setActionCode("ACT-001");
        blockIpAction.setName("Block Lab Network Source IP");
        blockIpAction.setDescription("Applies drop rules");
        blockIpAction.setCategory("DEFENSIVE_CONTAINMENT");
        blockIpAction.setTargetType("IP");
        blockIpAction.setRiskLevel(ResponseRiskLevel.MODERATE);
        blockIpAction.setRequiresApproval(true);
        catalogRepository.save(blockIpAction);

        disableUserAction = new ResponseActionDefinition();
        disableUserAction.setActionCode("ACT-002");
        disableUserAction.setName("Disable User Identity");
        disableUserAction.setDescription("Suspends account credentials");
        disableUserAction.setCategory("ACCESS_CONTROL");
        disableUserAction.setTargetType("USERNAME");
        disableUserAction.setRiskLevel(ResponseRiskLevel.HIGH);
        disableUserAction.setRequiresApproval(true);
        catalogRepository.save(disableUserAction);

        isolateHostAction = new ResponseActionDefinition();
        isolateHostAction.setActionCode("ACT-003");
        isolateHostAction.setName("Isolate Compromised Host Endpoint");
        isolateHostAction.setDescription("Network quarantine");
        isolateHostAction.setCategory("DEFENSIVE_CONTAINMENT");
        isolateHostAction.setTargetType("ASSET");
        isolateHostAction.setRiskLevel(ResponseRiskLevel.CRITICAL);
        isolateHostAction.setRequiresApproval(true);
        catalogRepository.save(isolateHostAction);

        evidenceAction = new ResponseActionDefinition();
        evidenceAction.setActionCode("ACT-007");
        evidenceAction.setName("Acquire Forensic Archive");
        evidenceAction.setDescription("Volatile memory triage");
        evidenceAction.setCategory("FORENSIC_ACQUISITION");
        evidenceAction.setTargetType("ASSET");
        evidenceAction.setRiskLevel(ResponseRiskLevel.LOW);
        evidenceAction.setRequiresApproval(false);
        catalogRepository.save(evidenceAction);

        // Seed Target Registry
        ResponseTargetRecord tgtIp = new ResponseTargetRecord();
        tgtIp.setTargetId("TGT-001");
        tgtIp.setTargetType("IP");
        tgtIp.setIdentifier("198.51.100.24");
        tgtIp.setDisplayName("Lab Attacker IP");
        tgtIp.setCriticality("STANDARD");
        targetRepository.save(tgtIp);

        ResponseTargetRecord tgtHost = new ResponseTargetRecord();
        tgtHost.setTargetId("TGT-002");
        tgtHost.setTargetType("HOST");
        tgtHost.setIdentifier("WIN-PROD-01");
        tgtHost.setDisplayName("Synthetic Windows Node");
        tgtHost.setCriticality("STANDARD");
        targetRepository.save(tgtHost);

        ResponseTargetRecord tgtUser = new ResponseTargetRecord();
        tgtUser.setTargetId("TGT-003");
        tgtUser.setTargetType("USER");
        tgtUser.setIdentifier("CORP\\analyst");
        tgtUser.setDisplayName("Synthetic Lab User");
        tgtUser.setCriticality("STANDARD");
        targetRepository.save(tgtUser);

        ResponseTargetRecord tgtRestricted = new ResponseTargetRecord();
        tgtRestricted.setTargetId("TGT-REST");
        tgtRestricted.setTargetType("IP");
        tgtRestricted.setIdentifier("203.0.113.99");
        tgtRestricted.setDisplayName("Restricted Non-Authorized Target");
        tgtRestricted.setTrustStatus("RESTRICTED");
        targetRepository.save(tgtRestricted);

        ResponseTargetRecord tgtRevoked = new ResponseTargetRecord();
        tgtRevoked.setTargetId("TGT-REV");
        tgtRevoked.setTargetType("IP");
        tgtRevoked.setIdentifier("203.0.113.100");
        tgtRevoked.setDisplayName("Revoked Target");
        tgtRevoked.setTrustStatus("REVOKED");
        targetRepository.save(tgtRevoked);

        ResponseTargetRecord tgtProtected = new ResponseTargetRecord();
        tgtProtected.setTargetId("TGT-PROT");
        tgtProtected.setTargetType("IP");
        tgtProtected.setIdentifier("10.0.0.1");
        tgtProtected.setDisplayName("Protected Core Gateway");
        tgtProtected.setTrustStatus("RESTRICTED");
        tgtProtected.setProtected(true);
        targetRepository.save(tgtProtected);

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
                null,
                new ObjectMapper()
        );
    }

    @Test
    @DisplayName("Security: Rejects CLI option injection (leading hyphen)")
    void testPolicyInputValidation_LeadingHyphenRejected() {
        PolicyEvaluationResultDto result = policyEngine.evaluate(
                blockIpAction,
                "--output=/tmp/pwn",
                ResponseExecutionMode.SIMULATION,
                "analyst-1",
                Map.of()
        );

        assertEquals(ResponsePolicyOutcome.DENY, result.getOutcome());
        assertTrue(result.getPolicyViolations().stream().anyMatch(v -> v.contains("hyphen")));
    }

    @Test
    @DisplayName("Security: Rejects whitespace argument injection")
    void testPolicyInputValidation_WhitespaceRejected() {
        PolicyEvaluationResultDto result = policyEngine.evaluate(
                blockIpAction,
                "198.51.100.24 10.0.0.1",
                ResponseExecutionMode.SIMULATION,
                "analyst-1",
                Map.of()
        );

        assertEquals(ResponsePolicyOutcome.DENY, result.getOutcome());
        assertTrue(result.getPolicyViolations().stream().anyMatch(v -> v.contains("whitespace")));
    }

    @Test
    @DisplayName("Security: Rejects shell metacharacters in target identifier")
    void testPolicyInputValidation_ShellMetacharactersRejected() {
        PolicyEvaluationResultDto result = policyEngine.evaluate(
                blockIpAction,
                "198.51.100.24; rm -rf /",
                ResponseExecutionMode.SIMULATION,
                "analyst-1",
                Map.of()
        );

        assertEquals(ResponsePolicyOutcome.DENY, result.getOutcome());
        assertTrue(result.getPolicyViolations().stream().anyMatch(v -> v.contains("metacharacters")));
    }

    @Test
    @DisplayName("Security: Protects critical infrastructure (127.0.0.1, localhost, gateway)")
    void testPolicyProtectedInfrastructure_LocalhostAndGatewayBlocked() {
        PolicyEvaluationResultDto r1 = policyEngine.evaluate(
                isolateHostAction,
                "127.0.0.1",
                ResponseExecutionMode.SIMULATION,
                "analyst-1",
                Map.of()
        );
        assertEquals(ResponsePolicyOutcome.DENY, r1.getOutcome());

        PolicyEvaluationResultDto r2 = policyEngine.evaluate(
                isolateHostAction,
                "localhost",
                ResponseExecutionMode.SIMULATION,
                "analyst-1",
                Map.of()
        );
        assertEquals(ResponsePolicyOutcome.DENY, r2.getOutcome());

        PolicyEvaluationResultDto r3 = policyEngine.evaluate(
                blockIpAction,
                "10.0.0.1",
                ResponseExecutionMode.SIMULATION,
                "analyst-1",
                Map.of()
        );
        assertEquals(ResponsePolicyOutcome.DENY, r3.getOutcome());
    }

    @Test
    @DisplayName("Security: Separation of Duties prevents proposer from self-approving high-risk actions")
    void testPolicySeparationOfDuties_ProposerCannotApproveHighRisk() {
        CreateProposalRequestDto req = new CreateProposalRequestDto();
        req.setActionCode("ACT-002"); // HIGH risk
        req.setTargetIdentifier("CORP\\analyst");
        req.setExecutionMode(ResponseExecutionMode.SIMULATION);

        ResponseProposalDto proposal = orchestrator.createProposal(req, "analyst-alice");
        assertEquals("PENDING_APPROVAL", proposal.getStatus());
        assertEquals("HIGH", proposal.getRiskLevel());

        // Self-approval attempt must fail
        ApproveProposalRequestDto approveReq = new ApproveProposalRequestDto("Self approving", false);
        InvalidActionException ex = assertThrows(InvalidActionException.class, () ->
                orchestrator.approveProposal(proposal.getId(), approveReq, "analyst-alice"));
        assertTrue(ex.getMessage().contains("Separation of Duties"));

        // Approval by different authorized analyst succeeds
        ResponseProposalDto approved = orchestrator.approveProposal(proposal.getId(), approveReq, "lead-bob");
        assertEquals("APPROVED", approved.getStatus());
        assertEquals("lead-bob", approved.getApprover());
    }

    @Test
    @DisplayName("Lifecycle: Low risk actions are auto-eligible for READY dispatch")
    void testProposalCreation_LowRiskAutoApproved() {
        CreateProposalRequestDto req = new CreateProposalRequestDto();
        req.setActionCode("ACT-007"); // LOW risk
        req.setTargetIdentifier("WIN-PROD-01");
        req.setExecutionMode(ResponseExecutionMode.SIMULATION);

        ResponseProposalDto proposal = orchestrator.createProposal(req, "analyst-charlie");
        assertEquals("READY", proposal.getStatus());
        assertEquals("LOW", proposal.getRiskLevel());
        assertFalse(proposal.isRequiresApproval());
    }

    @Test
    @DisplayName("End-to-End Simulation: Full proposal -> approval -> execution -> independent verification lifecycle")
    void testProposalApprovalAndExecution_EndToEndSimulationLifecycle() {
        // 1. Create Proposal
        CreateProposalRequestDto req = new CreateProposalRequestDto();
        req.setActionCode("ACT-001");
        req.setTargetIdentifier("198.51.100.24");
        req.setExecutionMode(ResponseExecutionMode.SIMULATION);

        ResponseProposalDto created = orchestrator.createProposal(req, "analyst-alice");
        assertEquals("PENDING_APPROVAL", created.getStatus());

        // 2. Approve Proposal
        ApproveProposalRequestDto approveReq = new ApproveProposalRequestDto("Confirmed lab perimeter drop", false);
        ResponseProposalDto approved = orchestrator.approveProposal(created.getId(), approveReq, "lead-bob");
        assertEquals("APPROVED", approved.getStatus());

        // 3. Execute Proposal
        ResponseProposalDto executed = orchestrator.executeProposal(created.getId(), "lead-bob");
        assertEquals("SIMULATED", executed.getStatus());
        assertNotNull(executed.getVerification());
        assertEquals("SIMULATION_ONLY", executed.getVerification().getStatus());
        assertTrue(executed.getVerification().isSimulation());
        assertEquals("SIMULATION_DRY_RUN", executed.getVerification().getVerificationMethod());
        assertTrue(executed.getVerification().getObservedOutcome().contains("Simulation only (dry-run)"));
        assertFalse(executed.getVerification().getObservedOutcome().contains("table query confirmed"));
    }

    @Test
    @DisplayName("Lifecycle: Proposal denial and cancellation")
    void testProposalDenialAndCancellation() {
        CreateProposalRequestDto req = new CreateProposalRequestDto();
        req.setActionCode("ACT-001");
        req.setTargetIdentifier("198.51.100.24");
        req.setExecutionMode(ResponseExecutionMode.SIMULATION);

        ResponseProposalDto p1 = orchestrator.createProposal(req, "analyst-alice");
        ResponseProposalDto denied = orchestrator.denyProposal(p1.getId(), "False positive investigation result", "lead-bob");
        assertEquals("DENIED", denied.getStatus());

        // Attempting to execute denied proposal fails
        assertThrows(InvalidActionException.class, () -> orchestrator.executeProposal(p1.getId(), "analyst-alice"));

        // Cancellation test
        ResponseProposalDto p2 = orchestrator.createProposal(req, "analyst-alice");
        ResponseProposalDto cancelled = orchestrator.cancelProposal(p2.getId(), "Incident closed prior to dispatch", "analyst-alice");
        assertEquals("CANCELLED", cancelled.getStatus());
    }

    @Test
    @DisplayName("Host Safety: Verifies all actions run in safe simulation without touching host environment")
    void testHostSafety_GuaranteesNoHostModification() {
        ResponseProposalRecord proposal = new ResponseProposalRecord();
        proposal.setProposalUuid("PROP-SAFE-001");
        proposal.setActionCode("ACT-003");
        proposal.setActionName("Isolate Compromised Host Endpoint");
        proposal.setActionType("DEFENSIVE_CONTAINMENT");
        proposal.setTargetIdentifier("WIN-PROD-01");
        proposal.setTargetType("ASSET");
        proposal.setExecutionMode(ResponseExecutionMode.SIMULATION);

        assertTrue(simulationAdapter.supports(proposal));

        ResponseExecutionResult result = simulationAdapter.dispatch(proposal);
        assertTrue(result.isSuccess());
        assertEquals("SIMULATION", result.getMode());
        assertTrue(result.getPayload().contains("simulatedArtifact"));
        assertTrue(result.getPayload().contains("Simulated action ran in safe lab containment"));
    }

    @Test
    @DisplayName("Security: Rejects unregistered, restricted, revoked, and mismatched-type targets (fail-closed)")
    void testPolicyFailClosed_UnregisteredTrustStatusAndTypeMismatchRejected() {
        PolicyEvaluationResultDto unregistered = policyEngine.evaluate(
                blockIpAction, "192.0.2.77", ResponseExecutionMode.SIMULATION, "analyst-1", Map.of()
        );
        assertEquals(ResponsePolicyOutcome.DENY, unregistered.getOutcome());
        assertTrue(unregistered.getPolicyViolations().stream().anyMatch(v -> v.contains("not registered")));

        PolicyEvaluationResultDto restricted = policyEngine.evaluate(
                blockIpAction, "203.0.113.99", ResponseExecutionMode.SIMULATION, "analyst-1", Map.of()
        );
        assertEquals(ResponsePolicyOutcome.DENY, restricted.getOutcome());
        assertTrue(restricted.getPolicyViolations().stream().anyMatch(v -> v.contains("AUTHORIZED")));

        PolicyEvaluationResultDto revoked = policyEngine.evaluate(
                blockIpAction, "203.0.113.100", ResponseExecutionMode.SIMULATION, "analyst-1", Map.of()
        );
        assertEquals(ResponsePolicyOutcome.DENY, revoked.getOutcome());

        PolicyEvaluationResultDto typeMismatch = policyEngine.evaluate(
                blockIpAction, "WIN-PROD-01", ResponseExecutionMode.SIMULATION, "analyst-1", Map.of()
        );
        assertEquals(ResponsePolicyOutcome.DENY, typeMismatch.getOutcome());
        assertTrue(typeMismatch.getPolicyViolations().stream().anyMatch(v -> v.contains("Target type mismatch")));
    }
}
