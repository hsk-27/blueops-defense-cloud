package com.blueops.response;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.UUID;

/**
 * Response Outcome Recording & Verification Engine (M6.10)
 * Evaluates execution outcomes truthfully:
 * - Simulation / contained sandbox executions are strictly recorded as SIMULATION_ONLY without fabricated telemetry.
 * - Live dispatches require real independent probe output before marking VERIFIED; otherwise status is UNAVAILABLE.
 */
@Service
public class ResponseVerificationEngine {

    private static final Logger log = LoggerFactory.getLogger(ResponseVerificationEngine.class);

    private final ResponseVerificationRepository verificationRepository;
    private final ObjectMapper objectMapper;

    public ResponseVerificationEngine(ResponseVerificationRepository verificationRepository) {
        this(verificationRepository, new ObjectMapper());
    }

    @Autowired
    public ResponseVerificationEngine(ResponseVerificationRepository verificationRepository, ObjectMapper objectMapper) {
        this.verificationRepository = verificationRepository;
        this.objectMapper = objectMapper;
    }

    /**
     * Evaluates remediation outcome honestly without fabricating verification claims.
     */
    @Transactional
    public ResponseVerificationRecord verifyOutcome(ResponseProposalRecord proposal, ResponseExecutionResult executionResult) {
        String verificationUuid = "VER-" + UUID.randomUUID().toString().substring(0, 8).toUpperCase();
        log.info("[VERIFICATION STARTED] Recording outcome for proposal [{}] (UUID: {}) mode [{}]",
                proposal.getActionCode(), proposal.getProposalUuid(), proposal.getExecutionMode());

        boolean proposalSimulation = proposal.getExecutionMode() == ResponseExecutionMode.SIMULATION;
        String executionModeLabel = executionResult.getMode() != null ? executionResult.getMode() : "UNKNOWN";
        boolean agentContainedSimulation = "SIMULATION".equalsIgnoreCase(executionModeLabel)
                || "LAB_CONTROLLED_EXECUTION".equalsIgnoreCase(executionModeLabel)
                || "CONTAINED_LAB_SANDBOX".equalsIgnoreCase(executionModeLabel);
        boolean isSimulation = proposalSimulation || agentContainedSimulation;

        String actionCode = proposal.getActionCode();
        String target = proposal.getTargetIdentifier();

        String expectedOutcome = buildExpectedOutcome(actionCode, target, isSimulation);
        String observedOutcome;
        String verificationMethod;
        VerificationStatus status;
        String evidencePayload;

        if (!executionResult.isSuccess()) {
            status = VerificationStatus.FAILED;
            verificationMethod = "DISPATCH_FAILURE";
            observedOutcome = String.format("Execution failed at dispatch stage (HTTP %d): %s",
                    executionResult.getStatusCode(), executionResult.getMessage());
            evidencePayload = toJson(buildEvidenceMap(
                    false, isSimulation, false, actionCode, target, executionModeLabel,
                    executionResult.getMessage(), null
            ));
        } else if (isSimulation) {
            status = VerificationStatus.SIMULATION_ONLY;
            verificationMethod = proposalSimulation ? "SIMULATION_DRY_RUN" : "AGENT_SIMULATION_ONLY";
            observedOutcome = proposalSimulation
                    ? String.format("Simulation only (dry-run): %s targeting %s completed in lab sandbox; no host mutation or real infrastructure probe occurred.", actionCode, target)
                    : String.format("Agent ran in simulated/contained mode (%s): %s against %s did not mutate host state and was not verified.", executionModeLabel, actionCode, target);
            evidencePayload = toJson(buildEvidenceMap(
                    true, true, false, actionCode, target, executionModeLabel,
                    observedOutcome, executionResult.getPayload()
            ));
        } else {
            JsonNode probeNode = parseIndependentProbe(executionResult.getPayload());
            if (probeNode != null && probeNode.has("verified") && probeNode.get("verified").isBoolean()) {
                boolean probeVerified = probeNode.get("verified").asBoolean();
                status = probeVerified ? VerificationStatus.VERIFIED : VerificationStatus.FAILED;
                verificationMethod = probeNode.path("method").asText("INDEPENDENT_STATE_PROBE");
                observedOutcome = probeNode.path("observedOutcome").asText(
                        probeVerified
                                ? "Independent probe confirmed target state change for " + target
                                : "Independent probe did not observe expected state change for " + target
                );
                evidencePayload = executionResult.getPayload();
            } else {
                status = VerificationStatus.UNAVAILABLE;
                verificationMethod = "NO_INDEPENDENT_PROBE";
                observedOutcome = String.format(
                        "Live action dispatched (HTTP %d, mode=%s), but no independent post-action probe data is available to verify %s on %s.",
                        executionResult.getStatusCode(), executionModeLabel, actionCode, target);
                evidencePayload = toJson(buildEvidenceMap(
                        true, false, false, actionCode, target, executionModeLabel,
                        observedOutcome, executionResult.getPayload()
                ));
            }
        }

        ResponseVerificationRecord record = new ResponseVerificationRecord();
        record.setVerificationUuid(verificationUuid);
        record.setProposal(proposal);
        record.setExecutionId(proposal.getExecutionId());
        record.setStatus(status);
        record.setVerificationMethod(verificationMethod);
        record.setExpectedOutcome(expectedOutcome);
        record.setObservedOutcome(observedOutcome);
        record.setEvidencePayload(evidencePayload);
        record.setSimulation(isSimulation);
        record.setVerifiedAt(Instant.now());

        ResponseVerificationRecord saved = verificationRepository.save(record);
        log.info("[VERIFICATION COMPLETED] Proposal [{}] status: {} (method={})",
                proposal.getProposalUuid(), status, verificationMethod);
        return saved;
    }

    private String buildExpectedOutcome(String actionCode, String target, boolean isSimulation) {
        String prefix = isSimulation ? "[Simulation dry-run] " : "";
        return switch (actionCode) {
            case "ACT-001", "P001" -> prefix + "Perimeter ingress DROP rule expected for IP: " + target;
            case "ACT-002", "P002" -> prefix + "Account lock expected for user: " + target;
            case "ACT-003", "P003" -> prefix + "Endpoint network quarantine expected for host: " + target;
            case "ACT-004", "P004" -> prefix + "Perimeter DROP rule removal expected for IP: " + target;
            case "ACT-005", "P005" -> prefix + "Account unlock expected for user: " + target;
            case "ACT-006", "P006" -> prefix + "Endpoint network reconnection expected for host: " + target;
            case "ACT-007", "P007" -> prefix + "Volatile forensic triage capture expected for host: " + target;
            default -> prefix + "Remediation action " + actionCode + " expected against target " + target;
        };
    }

    private JsonNode parseIndependentProbe(String payload) {
        if (payload == null || payload.isBlank()) {
            return null;
        }
        try {
            JsonNode root = objectMapper.readTree(payload);
            JsonNode probe = root.get("independentProbe");
            return (probe != null && probe.isObject()) ? probe : null;
        } catch (Exception ignored) {
            return null;
        }
    }

    private Map<String, Object> buildEvidenceMap(
            boolean dispatchSuccess,
            boolean simulated,
            boolean realProbePerformed,
            String actionCode,
            String target,
            String adapterMode,
            String summary,
            String rawAdapterPayload) {
        Map<String, Object> map = new LinkedHashMap<>();
        map.put("dispatchSuccess", dispatchSuccess);
        map.put("simulated", simulated);
        map.put("realProbePerformed", realProbePerformed);
        map.put("actionCode", actionCode);
        map.put("target", target);
        map.put("adapterMode", adapterMode);
        map.put("summary", summary);
        map.put("recordedAt", Instant.now().toString());
        if (rawAdapterPayload != null && !rawAdapterPayload.isBlank()) {
            map.put("adapterResponseExcerpt", rawAdapterPayload.length() > 500
                    ? rawAdapterPayload.substring(0, 500)
                    : rawAdapterPayload);
        }
        return map;
    }

    private String toJson(Map<String, Object> data) {
        try {
            return objectMapper.writeValueAsString(data);
        } catch (Exception e) {
            return "{\"error\":\"JSON_SERIALIZATION_FAILED\"}";
        }
    }
}
