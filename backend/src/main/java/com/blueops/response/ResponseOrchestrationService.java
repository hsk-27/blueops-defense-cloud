package com.blueops.response;

import com.blueops.assets.Asset;
import com.blueops.assets.AssetRepository;
import com.blueops.assets.AssetStatus;
import com.blueops.audit.AuditService;
import com.blueops.common.exceptions.InvalidActionException;
import com.blueops.common.exceptions.ResourceNotFoundException;
import com.blueops.incidents.Incident;
import com.blueops.incidents.IncidentRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
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
    private final AuditService auditService;
    private final ResponsePolicyValidator policyValidator;
    private final RestTemplate restTemplate;

    @Value("${blueops.response-agent.url:http://localhost:5000}")
    private String responseAgentUrl;

    @Value("${blueops.response-agent.simulation-mode:true}")
    private boolean defaultSimulationMode;

    @Autowired
    public ResponseOrchestrationService(
            ResponsePlaybookRepository playbookRepository,
            ResponseActionRepository actionRepository,
            ResponseExecutionRepository executionRepository,
            IncidentRepository incidentRepository,
            AssetRepository assetRepository,
            HmacSignatureService hmacSignatureService,
            RestTemplateBuilder restTemplateBuilder,
            @Autowired(required = false) AuditService auditService,
            @Autowired(required = false) ResponsePolicyValidator policyValidator) {
        this.playbookRepository = playbookRepository;
        this.actionRepository = actionRepository;
        this.executionRepository = executionRepository;
        this.incidentRepository = incidentRepository;
        this.assetRepository = assetRepository;
        this.hmacSignatureService = hmacSignatureService;
        this.auditService = auditService;
        this.policyValidator = policyValidator;
        this.restTemplate = restTemplateBuilder
                .setConnectTimeout(Duration.ofSeconds(3))
                .setReadTimeout(Duration.ofSeconds(5))
                .build();
    }

    public ResponseOrchestrationService(
            ResponsePlaybookRepository playbookRepository,
            ResponseActionRepository actionRepository,
            ResponseExecutionRepository executionRepository,
            IncidentRepository incidentRepository,
            AssetRepository assetRepository,
            HmacSignatureService hmacSignatureService,
            RestTemplateBuilder restTemplateBuilder) {
        this(playbookRepository, actionRepository, executionRepository, incidentRepository, assetRepository, hmacSignatureService, restTemplateBuilder, null, null);
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

        Asset targetAsset = null;
        if (request.getTargetAssetId() != null) {
            targetAsset = assetRepository.findById(request.getTargetAssetId()).orElse(null);
        } else if (request.getTargetIdentifier() != null) {
            targetAsset = assetRepository.findByHostnameIgnoreCase(request.getTargetIdentifier().trim())
                    .or(() -> assetRepository.findByIpAddress(request.getTargetIdentifier().trim()))
                    .orElse(null);
        }

        // Validate action request against policy bounds (RSP-001)
        if (policyValidator != null) {
            policyValidator.validateRequest(playbook, request.getTargetIdentifier(), targetAsset, request.isSimulation() || defaultSimulationMode);
        }

        boolean requiresApproval = playbook.isRequiresApproval()
                || (targetAsset != null && "CRITICAL".equalsIgnoreCase(targetAsset.getCriticality()));

        ResponseAction action = new ResponseAction();
        action.setActionUuid(UUID.randomUUID().toString());
        action.setPlaybookCode(playbook.getPlaybookCode());
        action.setTargetIdentifier(request.getTargetIdentifier());
        action.setRequestedBy(requestedBy);
        action.setSimulation(request.isSimulation() || defaultSimulationMode);
        action.setApprovalStatus(requiresApproval ? "PENDING" : "AUTO_APPROVED");
        action.setExecutionStatus("NOT_STARTED");
        action.setTargetAsset(targetAsset);

        if (request.getIncidentId() != null) {
            Incident incident = incidentRepository.findById(request.getIncidentId()).orElse(null);
            action.setIncident(incident);
        }

        ResponseAction saved = actionRepository.save(action);

        if (auditService != null) {
            auditService.recordEvent(requestedBy, "RESPONSE_ACTION_REQUESTED", "ResponseAction", saved.getActionUuid(), null,
                    "Playbook: " + playbook.getPlaybookCode() + ", Target: " + saved.getTargetIdentifier());
        }

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

        if (auditService != null) {
            auditService.recordEvent(approvedBy, "RESPONSE_ACTION_APPROVED", "ResponseAction", action.getActionUuid(), null,
                    "Approved playbook: " + action.getPlaybookCode() + " for target: " + action.getTargetIdentifier());
        }

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

        if (auditService != null) {
            auditService.recordEvent(rejectedBy, "RESPONSE_ACTION_REJECTED", "ResponseAction", action.getActionUuid(), null,
                    "Reason: " + (reason != null ? reason : "Analyst rejected action"));
        }

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

        ResponsePlaybook reversalPlaybook = playbookRepository.findByActionType(reverseActionType)
                .orElseThrow(() -> new InvalidActionException("No reversal playbook configured for action type: " + reverseActionType));

        ResponseAction rollback = new ResponseAction();
        rollback.setActionUuid(UUID.randomUUID().toString());
        rollback.setPlaybookCode(reversalPlaybook.getPlaybookCode());
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

        if (auditService != null) {
            auditService.recordEvent(requestedBy, "RESPONSE_ACTION_ROLLBACK", "ResponseAction", savedRollback.getActionUuid(), null,
                    "Rollback executed for original action: " + originalAction.getActionUuid() + " via playbook: " + reversalPlaybook.getPlaybookCode());
        }

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
        // Enforce centralized policy validation on all execution paths (request, approve, rollback)
        if (policyValidator != null) {
            ResponsePlaybook playbook = getPlaybook(action.getPlaybookCode());
            policyValidator.validateRequest(playbook, action.getTargetIdentifier(), action.getTargetAsset(), action.isSimulation());
        }

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

            // Update asset status based on action type
            updateTargetAssetStatus(action);
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
                boolean isSuccess = response.getStatusCode().is2xxSuccessful();
                execution.setSuccess(isSuccess);
                execution.setStatusCode(response.getStatusCode().value());
                execution.setResponsePayload(response.getBody());
                execution.setVerificationPassed(isSuccess);

                action.setExecutionStatus(isSuccess ? "SUCCEEDED" : "FAILED");
                if (isSuccess) {
                    updateTargetAssetStatus(action);
                }
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

    private void updateTargetAssetStatus(ResponseAction action) {
        Asset asset = action.getTargetAsset();
        if (asset == null && action.getTargetIdentifier() != null) {
            asset = assetRepository.findByHostnameIgnoreCase(action.getTargetIdentifier().trim())
                    .or(() -> assetRepository.findByIpAddress(action.getTargetIdentifier().trim()))
                    .orElse(null);
            if (asset != null) {
                action.setTargetAsset(asset);
            }
        }
        if (asset == null) return;
        ResponsePlaybook playbook = playbookRepository.findByPlaybookCode(action.getPlaybookCode()).orElse(null);
        String actionType = playbook != null ? playbook.getActionType() : "";

        if ("ISOLATE_HOST".equalsIgnoreCase(actionType) || "P003".equalsIgnoreCase(action.getPlaybookCode())) {
            asset.setStatus(AssetStatus.ISOLATED);
            assetRepository.save(asset);
        } else if ("RECONNECT_HOST".equalsIgnoreCase(actionType) || "P006".equalsIgnoreCase(action.getPlaybookCode())) {
            asset.setStatus(AssetStatus.HEALTHY);
            assetRepository.save(asset);
        }
    }
}
