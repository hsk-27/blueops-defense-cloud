package com.blueops.response;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.mock.http.client.MockClientHttpRequest;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.test.web.client.MockRestServiceServer;
import org.springframework.web.client.RestTemplate;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.*;
import static org.springframework.test.web.client.ExpectedCount.times;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.method;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.requestTo;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withSuccess;

class AgentResponseContractTest {

    private static final String TEST_SECRET = "9f8e7d6c5b4a39281716151413121110090807060504030201f0e1d2c3b4a596";

    private HmacSignatureService hmacSignatureService;
    private RestTemplate restTemplate;
    private MockRestServiceServer mockAgentServer;
    private RestrictedAgentResponseAdapter adapter;
    private ResponseVerificationEngine verificationEngine;
    private final ObjectMapper objectMapper = new ObjectMapper();
    private final List<JsonNode> capturedAgentRequests = new ArrayList<>();
    private final AtomicReference<String> serverMode = new AtomicReference<>("LAB_CONTROLLED_EXECUTION");

    @BeforeEach
    void setUp() {
        hmacSignatureService = new HmacSignatureService(TEST_SECRET);
        restTemplate = new RestTemplate();
        mockAgentServer = MockRestServiceServer.bindTo(restTemplate).build();
        adapter = new RestrictedAgentResponseAdapter(hmacSignatureService, restTemplate, objectMapper);
        ReflectionTestUtils.setField(adapter, "responseAgentUrl", "http://localhost:5000");
        verificationEngine = new ResponseVerificationEngine(new M6TestStubs.StubVerificationRepository(), objectMapper);
        capturedAgentRequests.clear();
    }

    @Test
    void testSupportedCatalogActionsMapAndSignCorrectly() {
        Map<String, List<String>> contract = Map.of(
                "ACT-001", List.of("BLOCK_IP", "P001", "198.51.100.24"),
                "ACT-002", List.of("DISABLE_USER", "P002", "corp.analyst"),
                "ACT-003", List.of("ISOLATE_HOST", "P003", "WIN-PROD-01"),
                "ACT-004", List.of("RESTORE_IP", "P004", "198.51.100.24"),
                "ACT-005", List.of("ENABLE_USER", "P005", "corp.analyst"),
                "ACT-006", List.of("RECONNECT_HOST", "P006", "WIN-PROD-01"),
                "ACT-007", List.of("COLLECT_EVIDENCE", "P007", "WIN-PROD-01")
        );

        mockAgentServer.expect(times(7), requestTo("http://localhost:5000/api/v1/execute"))
                .andExpect(method(HttpMethod.POST))
                .andExpect(request -> {
                    MockClientHttpRequest mockReq = (MockClientHttpRequest) request;
                    String payload = mockReq.getBodyAsString();
                    String sig = mockReq.getHeaders().getFirst("X-BlueOps-Signature");
                    String ts = mockReq.getHeaders().getFirst("X-BlueOps-Timestamp");
                    assertNotNull(mockReq.getHeaders().getFirst("X-BlueOps-ActionId"));
                    assertTrue(hmacSignatureService.verifySignature(payload, Long.parseLong(ts), sig));
                    capturedAgentRequests.add(objectMapper.readTree(payload));
                })
                .andRespond(request -> {
                    MockClientHttpRequest mockReq = (MockClientHttpRequest) request;
                    JsonNode reqJson = objectMapper.readTree(mockReq.getBodyAsString());
                    String resp = objectMapper.writeValueAsString(Map.of(
                            "status", "SUCCESS",
                            "mode", serverMode.get(),
                            "action", reqJson.path("action").asText(),
                            "actionCode", reqJson.path("actionCode").asText(),
                            "playbook", reqJson.path("playbookCode").asText(),
                            "target", reqJson.path("target").asText(),
                            "remediation", "Mocked agent dispatch received"
                    ));
                    return withSuccess(resp, MediaType.APPLICATION_JSON).createResponse(request);
                });

        for (var entry : contract.entrySet()) {
            ResponseProposalRecord proposal = buildProposal(entry.getKey(), entry.getValue().get(2), ResponseExecutionMode.LIVE);
            ResponseExecutionResult result = adapter.dispatch(proposal);
            assertTrue(result.isSuccess(), "Expected success for " + entry.getKey());
            assertEquals(200, result.getStatusCode());
        }

        mockAgentServer.verify();
        assertEquals(7, capturedAgentRequests.size());
        for (JsonNode req : capturedAgentRequests) {
            String code = req.get("actionCode").asText();
            assertEquals(contract.get(code).get(0), req.get("action").asText());
            assertEquals(contract.get(code).get(1), req.get("playbookCode").asText());
        }
    }

    @Test
    void testUnsupportedAct008RejectedWithoutCallingAgent() {
        ResponseProposalRecord unsupported = buildProposal("ACT-008", "WIN-PROD-01", ResponseExecutionMode.LIVE);
        ResponseExecutionResult result = adapter.dispatch(unsupported);

        assertFalse(result.isSuccess());
        assertEquals(501, result.getStatusCode());
        assertEquals("UNSUPPORTED_ACTION", result.getMode());
        mockAgentServer.verify();

        ResponseVerificationRecord verification = verificationEngine.verifyOutcome(unsupported, result);
        assertEquals(VerificationStatus.FAILED, verification.getStatus());
    }

    @Test
    void testVerificationDoesNotFabricateHashesOrMarkLiveWithoutProbeAsVerified() {
        serverMode.set("LIVE_HOST_EXECUTION");
        mockAgentServer.expect(times(2), requestTo("http://localhost:5000/api/v1/execute"))
                .andExpect(method(HttpMethod.POST))
                .andRespond(request -> {
                    String resp = objectMapper.writeValueAsString(Map.of(
                            "status", "SUCCESS",
                            "mode", serverMode.get(),
                            "remediation", "Dispatched"
                    ));
                    return withSuccess(resp, MediaType.APPLICATION_JSON).createResponse(request);
                });

        ResponseProposalRecord liveProposal = buildProposal("ACT-007", "WIN-PROD-01", ResponseExecutionMode.LIVE);
        ResponseExecutionResult liveResult = adapter.dispatch(liveProposal);

        ResponseVerificationRecord liveVerification = verificationEngine.verifyOutcome(liveProposal, liveResult);
        assertEquals(VerificationStatus.UNAVAILABLE, liveVerification.getStatus());
        assertEquals("NO_INDEPENDENT_PROBE", liveVerification.getVerificationMethod());
        assertFalse(liveVerification.isSimulation());
        assertFalse(liveVerification.getEvidencePayload().contains("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"));
        assertFalse(liveVerification.getEvidencePayload().contains("24115200"));

        serverMode.set("CONTAINED_LAB_SANDBOX");
        ResponseProposalRecord containedProposal = buildProposal("ACT-001", "198.51.100.24", ResponseExecutionMode.LIVE);
        ResponseExecutionResult containedResult = adapter.dispatch(containedProposal);
        ResponseVerificationRecord containedVerification = verificationEngine.verifyOutcome(containedProposal, containedResult);
        assertEquals(VerificationStatus.SIMULATION_ONLY, containedVerification.getStatus());
        assertTrue(containedVerification.isSimulation());

        mockAgentServer.verify();
    }

    private ResponseProposalRecord buildProposal(String actionCode, String target, ResponseExecutionMode mode) {
        ResponseProposalRecord record = new ResponseProposalRecord();
        record.setId(1L);
        record.setProposalUuid("PROP-TEST-" + actionCode);
        record.setActionCode(actionCode);
        record.setActionName("Test Action " + actionCode);
        record.setActionType("DEFENSIVE_CONTAINMENT");
        record.setTargetIdentifier(target);
        record.setTargetType("ASSET");
        record.setExecutionMode(mode);
        record.setProposedBy("analyst");
        record.setRiskLevel(ResponseRiskLevel.MODERATE);
        record.setPolicyOutcome(ResponsePolicyOutcome.ALLOW);
        record.setStatus(ProposalStatus.APPROVED);
        return record;
    }
}
