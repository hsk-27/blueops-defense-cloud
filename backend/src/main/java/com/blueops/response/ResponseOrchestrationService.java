package com.blueops.response;

import com.blueops.assets.Asset;
import com.blueops.assets.AssetRepository;
import com.blueops.assets.AssetStatus;
import com.blueops.common.exceptions.InvalidActionException;
import com.blueops.common.exceptions.ResourceNotFoundException;
import com.blueops.incidents.Incident;
import com.blueops.incidents.IncidentRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.web.client.RestTemplateBuilder;
import org.springframework.http.*;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.client.RestTemplate;

import java.time.Duration;
import java.time.Instant;
import java.util.*;
import java.util.stream.Collectors;

@Service
public class ResponseOrchestrationService {

    private static final Logger log = LoggerFactory.getLogger(ResponseOrchestrationService.class);

    private final ResponsePlaybookRepository playbookRepository;
    private final ResponseActionRepository actionRepository;
    private final ResponseExecutionRepository executionRepository;
    private final IncidentRepository incidentRepository;
    private final AssetRepository assetRepository;
    private final HmacSignatureService hmacSignatureService;
    private final RestTemplate restTemplate;

    @Value("${blueops.response-agent.url:http://localhost:5000}")
    private String responseAgentUrl;

    @Value("${blueops.response-agent.simulation-mode:true}")
    private boolean defaultSimulationMode;

    public ResponseOrchestrationService(
            ResponsePlaybookRepository playbookRepository,
            ResponseActionRepository actionRepository,
            ResponseExecutionRepository executionRepository,
            IncidentRepository incidentRepository,
            AssetRepository assetRepository,
            HmacSignatureService hmacSignatureService,
            RestTemplateBuilder restTemplateBuilder) {
        this.playbookRepository = playbookRepository;
        this.actionRepository = actionRepository;
        this.executionRepository = executionRepository;
        this.incidentRepository = incidentRepository;
        this.assetRepository = assetRepository;
        this.hmacSignatureService = hmacSignatureService;
        this.restTemplate = restTemplateBuilder
                .setConnectTimeout(Duration.ofSeconds(3))
                .setReadTimeout(Duration.ofSeconds(5))
                .build();
    }

    @Transactional(readOnly = true)
    public List<ResponsePlaybook> getPlaybooks() {
        return playbookRepository.findAll();
    }

    @Transactional(readOnly = true)
    public ResponsePlaybook getPlaybook(String code) {
        return playbookRepository.findByPlaybookCode(code)
                .orElseThrow(() -> new ResourceNotFoundException("Playbook", "code", code));
    }

    @Transactional
    public ResponseActionDto requestAction(ResponseActionRequestDto request, String requestedBy) {
        ResponsePlaybook playbook = getPlaybook(request.getPlaybookCode());

        ResponseAction action = new ResponseAction();
        action.setActionUuid(UUID.randomUUID().toString());
        action.setPlaybookCode(playbook.getPlaybookCode());
        action.setTargetIdentifier(request.getTargetIdentifier());
        action.setRequestedBy(requestedBy);
        action.setSimulation(request.isSimulation() || defaultSimulationMode);
        action.setApprovalStatus(playbook.isRequiresApproval() ? "PENDING" : "AUTO_APPROVED");
        action.setExecutionStatus("NOT_STARTED");

        if (request.getIncidentId() != null) {
            Incident incident = incidentRepository.findById(request.getIncidentId()).orElse(null);
            action.setIncident(incident);
        }

        if (request.getTargetAssetId() != null) {
            Asset asset = assetRepository.findById(request.getTargetAssetId()).orElse(null);
            action.setTargetAsset(asset);
        }

        ResponseAction saved = actionRepository.save(action);

        if (!playbook.isRequiresApproval()) {
            executeActionInternal(saved);
        }

        return new ResponseActionDto(saved);
    }

    @Transactional
    public ResponseActionDto approveAction(Long actionId, String approvedBy) {
        ResponseAction action = actionRepository.findById(actionId)
                .orElseThrow(() -> new ResourceNotFoundException("ResponseAction", "id", actionId));

        if (!"PENDING".equalsIgnoreCase(action.getApprovalStatus())) {
            throw new InvalidActionException("Action is not pending approval. Current state: " + action.getApprovalStatus());
        }

        action.setApprovalStatus("APPROVED");
        action.setApprovedBy(approvedBy);
        action.setApprovedAt(Instant.now());
        action.setUpdatedAt(Instant.now());

        executeActionInternal(action);

        return new ResponseActionDto(actionRepository.save(action));
    }

    @Transactional
    public ResponseActionDto rejectAction(Long actionId, String rejectedBy, String reason) {
        ResponseAction action = actionRepository.findById(actionId)
                .orElseThrow(() -> new ResourceNotFoundException("ResponseAction", "id", actionId));

        action.setApprovalStatus("REJECTED");
        action.setApprovedBy(rejectedBy);
        action.setExecutionStatus("CANCELLED");
        action.setUpdatedAt(Instant.now());

        return new ResponseActionDto(actionRepository.save(action));
    }

    @Transactional
    public ResponseExecutionDto executeAction(Long actionId) {
        ResponseAction action = actionRepository.findById(actionId)
                .orElseThrow(() -> new ResourceNotFoundException("ResponseAction", "id", actionId));

        if (!"APPROVED".equalsIgnoreCase(action.getApprovalStatus()) && !"AUTO_APPROVED".equalsIgnoreCase(action.getApprovalStatus())) {
            throw new InvalidActionException("Cannot execute unapproved action. Status: " + action.getApprovalStatus());
        }

        return new ResponseExecutionDto(executeActionInternal(action));
    }

    @Transactional
    public ResponseActionDto rollbackAction(Long actionId, String requestedBy) {
        ResponseAction originalAction = actionRepository.findById(actionId)
                .orElseThrow(() -> new ResourceNotFoundException("ResponseAction", "id", actionId));

        if (!"SUCCEEDED".equalsIgnoreCase(originalAction.getExecutionStatus())) {
            throw new InvalidActionException("Cannot rollback an action that did not succeed. Current status: " + originalAction.getExecutionStatus());
        }

        ResponsePlaybook originalPlaybook = getPlaybook(originalAction.getPlaybookCode());
        if (!originalPlaybook.isRollbackSupported()) {
            throw new InvalidActionException("Rollback is not supported for playbook: " + originalPlaybook.getPlaybookCode());
        }

        String reverseActionType;
        switch (originalPlaybook.getActionType()) {
            case "BLOCK_IP": reverseActionType = "RESTORE_IP"; break;
            case "DISABLE_USER": reverseActionType = "ENABLE_USER"; break;
            case "ISOLATE_HOST": reverseActionType = "RECONNECT_HOST"; break;
            default: throw new InvalidActionException("Unknown reversal action type for " + originalPlaybook.getActionType());
        }

        ResponseAction rollback = new ResponseAction();
        rollback.setActionUuid(UUID.randomUUID().toString());
        rollback.setPlaybookCode("ROLLBACK_" + originalAction.getPlaybookCode());
        rollback.setTargetIdentifier(originalAction.getTargetIdentifier());
        rollback.setTargetAsset(originalAction.getTargetAsset());
        rollback.setIncident(originalAction.getIncident());
        rollback.setRequestedBy(requestedBy);
        rollback.setApprovalStatus("APPROVED");
        rollback.setApprovedBy(requestedBy);
        rollback.setApprovedAt(Instant.now());
        rollback.setSimulation(originalAction.isSimulation());
        rollback.setReversalAction(originalAction);

        ResponseAction savedRollback = actionRepository.save(rollback);
        executeActionInternal(savedRollback);

        originalAction.setExecutionStatus("ROLLED_BACK");
        originalAction.setReversalAction(savedRollback);
        actionRepository.save(originalAction);

        return new ResponseActionDto(savedRollback);
    }

    @Transactional(readOnly = true)
    public List<ResponseExecutionDto> getAllExecutions() {
        return executionRepository.findTop50ByOrderByExecutedAtDesc().stream()
                .map(ResponseExecutionDto::new)
                .collect(Collectors.toList());
    }

    @Transactional(readOnly = true)
    public List<ResponseActionDto> getRecentActions() {
        return actionRepository.findTop25ByOrderByCreatedAtDesc().stream()
                .map(ResponseActionDto::new)
                .collect(Collectors.toList());
    }

    private ResponseExecution executeActionInternal(ResponseAction action) {
        long startTime = System.currentTimeMillis();
        action.setExecutionStatus("IN_PROGRESS");
        actionRepository.save(action);

        ResponseExecution execution = new ResponseExecution();
        execution.setAction(action);
        execution.setExecutedAt(Instant.now());

        if (action.isSimulation()) {
            // Simulated execution
            long duration = 45L + (long) (Math.random() * 30);
            execution.setExecutionDurationMs(duration);
            execution.setSuccess(true);
            execution.setStatusCode(200);
            execution.setVerificationPassed(true);
            execution.setResponsePayload(String.format(
                    "{\"mode\":\"SIMULATION\",\"status\":\"SUCCESS\",\"playbook\":\"%s\",\"target\":\"%s\",\"message\":\"Simulated lab action applied and verified successfully.\"}",
                    action.getPlaybookCode(), action.getTargetIdentifier()
            ));

            action.setExecutionStatus("SUCCEEDED");
            actionRepository.save(action);

            // Update asset status if target is an asset isolation playbook
            if ("P003".equalsIgnoreCase(action.getPlaybookCode()) && action.getTargetAsset() != null) {
                Asset asset = action.getTargetAsset();
                asset.setStatus(AssetStatus.ISOLATED);
                assetRepository.save(asset);
            }
        } else {
            // Live restricted lab agent execution with HMAC signature
            try {
                long timestamp = Instant.now().getEpochSecond();
                String payload = String.format("{\"actionUuid\":\"%s\",\"playbookCode\":\"%s\",\"target\":\"%s\"}",
                        action.getActionUuid(), action.getPlaybookCode(), action.getTargetIdentifier());
                String signature = hmacSignatureService.signPayload(payload, timestamp);

                HttpHeaders headers = new HttpHeaders();
                headers.setContentType(MediaType.APPLICATION_JSON);
                headers.set("X-BlueOps-Signature", signature);
                headers.set("X-BlueOps-Timestamp", String.valueOf(timestamp));
                headers.set("X-BlueOps-ActionId", action.getActionUuid());

                HttpEntity<String> entity = new HttpEntity<>(payload, headers);
                ResponseEntity<String> response = restTemplate.postForEntity(responseAgentUrl + "/api/v1/execute", entity, String.class);

                long duration = System.currentTimeMillis() - startTime;
                execution.setExecutionDurationMs(duration);
                execution.setSuccess(response.getStatusCode().is2xxSuccessful());
                execution.setStatusCode(response.getStatusCode().value());
                execution.setResponsePayload(response.getBody());
                execution.setVerificationPassed(response.getStatusCode().is2xxSuccessful());

                action.setExecutionStatus(response.getStatusCode().is2xxSuccessful() ? "SUCCEEDED" : "FAILED");
            } catch (Exception ex) {
                log.warn("Response agent execution failed: {}", ex.getMessage());
                long duration = System.currentTimeMillis() - startTime;
                execution.setExecutionDurationMs(duration);
                execution.setSuccess(false);
                execution.setStatusCode(503);
                execution.setErrorMessage("Agent communication error: " + ex.getMessage());
                execution.setVerificationPassed(false);
                action.setExecutionStatus("FAILED");
            }
            actionRepository.save(action);
        }

        return executionRepository.save(execution);
    }
}
