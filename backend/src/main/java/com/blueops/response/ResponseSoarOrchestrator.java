package com.blueops.response;

import com.blueops.audit.AuditService;
import com.blueops.common.exceptions.InvalidActionException;
import com.blueops.common.exceptions.ResourceNotFoundException;
import com.blueops.incidents.Incident;
import com.blueops.incidents.IncidentRepository;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Duration;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Controlled SOAR Response Orchestrator (M6.9, M6.12)
 * Coordinates proposal lifecycle, policy governance, multi-stage approval,
 * bounded adapter dispatch, idempotency, independent verification, and full auditability.
 */
@Service
public class ResponseSoarOrchestrator {

    private static final Logger log = LoggerFactory.getLogger(ResponseSoarOrchestrator.class);

    private final ResponseProposalRepository proposalRepository;
    private final ResponseActionCatalogRepository catalogRepository;
    private final ResponseTargetRepository targetRepository;
    private final ResponseVerificationRepository verificationRepository;
    private final IncidentRepository incidentRepository;
    private final ResponsePolicyEngine policyEngine;
    private final ResponseVerificationEngine verificationEngine;
    private final List<ResponseAdapter> responseAdapters;
    private final AuditService auditService;
    private final ObjectMapper objectMapper;

    // Concurrency / Idempotency protection lock set
    private final Set<String> activeExecutionLocks = ConcurrentHashMap.newKeySet();

    public ResponseSoarOrchestrator(
            ResponseProposalRepository proposalRepository,
            ResponseActionCatalogRepository catalogRepository,
            ResponseTargetRepository targetRepository,
            ResponseVerificationRepository verificationRepository,
            IncidentRepository incidentRepository,
            ResponsePolicyEngine policyEngine,
            ResponseVerificationEngine verificationEngine,
            List<ResponseAdapter> responseAdapters,
            AuditService auditService,
            ObjectMapper objectMapper) {
        this.proposalRepository = proposalRepository;
        this.catalogRepository = catalogRepository;
        this.targetRepository = targetRepository;
        this.verificationRepository = verificationRepository;
        this.incidentRepository = incidentRepository;
        this.policyEngine = policyEngine;
        this.verificationEngine = verificationEngine;
        this.responseAdapters = responseAdapters;
        this.auditService = auditService;
        this.objectMapper = objectMapper;
    }

    // --- Action Catalog & Targets Querying ---

    @Transactional(readOnly = true)
    public List<ResponseActionCatalogDto> getActionCatalog() {
        return catalogRepository.findByIsEnabledTrue().stream()
                .map(ResponseActionCatalogDto::new)
                .toList();
    }

    @Transactional(readOnly = true)
    public List<ResponseTargetDto> getAuthorizedTargets() {
        return targetRepository.findAll().stream()
                .map(ResponseTargetDto::new)
                .toList();
    }

    // --- Proposal Creation & Lifecycle ---

    @Transactional
    public ResponseProposalDto createProposal(CreateProposalRequestDto request, String actor) {
        ResponseActionDefinition actionDef = catalogRepository.findByActionCode(request.getActionCode())
                .orElseThrow(() -> new ResourceNotFoundException("ResponseAction", "code", request.getActionCode()));

        // Pre-evaluation check against Policy Engine
        PolicyEvaluationResultDto policyResult = policyEngine.evaluate(
                actionDef,
                request.getTargetIdentifier(),
                request.getExecutionMode(),
                actor,
                request.getParameters()
        );

        if (policyResult.getOutcome() == ResponsePolicyOutcome.DENY || policyResult.getOutcome() == ResponsePolicyOutcome.INVALID) {
            throw new InvalidActionException("Response proposal rejected by policy: " + policyResult.getReason());
        }

        // Enforce execution mode constraint from policy
        ResponseExecutionMode effectiveMode = request.getExecutionMode();
        if (policyResult.getOutcome() == ResponsePolicyOutcome.SIMULATION_ONLY) {
            effectiveMode = ResponseExecutionMode.SIMULATION;
        }

        Incident incident = null;
        if (request.getIncidentId() != null) {
            incident = incidentRepository.findById(request.getIncidentId()).orElse(null);
        }

        String paramsJson = null;
        try {
            if (request.getParameters() != null) {
                paramsJson = objectMapper.writeValueAsString(request.getParameters());
            }
        } catch (Exception ignored) {}

        ResponseProposalRecord proposal = new ResponseProposalRecord();
        proposal.setProposalUuid("PROP-" + UUID.randomUUID().toString().substring(0, 10).toUpperCase());
        proposal.setIncident(incident);
        proposal.setFindingId(request.getFindingId());
        proposal.setCorrelationId(request.getCorrelationId());
        proposal.setActionCode(actionDef.getActionCode());
        proposal.setActionName(actionDef.getName());
        proposal.setActionType(actionDef.getCategory());
        proposal.setTargetCanonicalId(request.getTargetCanonicalId());
        proposal.setTargetIdentifier(request.getTargetIdentifier());
        proposal.setTargetType(actionDef.getTargetType());
        proposal.setParametersJson(paramsJson);
        proposal.setProposedBy(actor);
        proposal.setProposedAt(Instant.now());
        proposal.setRiskLevel(policyResult.getRiskLevel());
        proposal.setExecutionMode(effectiveMode);
        proposal.setPolicyOutcome(policyResult.getOutcome());
        proposal.setPolicyReason(policyResult.getReason());
        proposal.setRequiresApproval(policyResult.isRequiresApproval());
        proposal.setExpiresAt(Instant.now().plus(Duration.ofHours(24)));

        // If low risk and policy allows immediate execution, set READY, otherwise PENDING_APPROVAL
        if (policyResult.getOutcome() == ResponsePolicyOutcome.ALLOW && !policyResult.isRequiresApproval()) {
            proposal.setStatus(ProposalStatus.READY);
        } else {
            proposal.setStatus(ProposalStatus.PENDING_APPROVAL);
        }

        ResponseProposalRecord saved = proposalRepository.save(proposal);

        if (auditService != null) {
            auditService.recordEvent(actor, "RESPONSE_PROPOSAL_CREATED", "ResponseProposal", saved.getProposalUuid(), null,
                    String.format("Action: %s, Target: %s, Risk: %s, Status: %s",
                            saved.getActionCode(), saved.getTargetIdentifier(), saved.getRiskLevel(), saved.getStatus()));
        }

        return toDto(saved);
    }

    // --- Policy Preview (Pre-flight) ---

    @Transactional(readOnly = true)
    public PolicyEvaluationResultDto evaluatePolicyPreview(CreateProposalRequestDto request, String actor) {
        ResponseActionDefinition actionDef = catalogRepository.findByActionCode(request.getActionCode())
                .orElseThrow(() -> new ResourceNotFoundException("ResponseAction", "code", request.getActionCode()));

        return policyEngine.evaluate(
                actionDef,
                request.getTargetIdentifier(),
                request.getExecutionMode(),
                actor,
                request.getParameters()
        );
    }

    // --- Proposal Approval & Denial ---

    @Transactional
    public ResponseProposalDto approveProposal(Long proposalId, ApproveProposalRequestDto request, String approver) {
        ResponseProposalRecord proposal = proposalRepository.findById(proposalId)
                .orElseThrow(() -> new ResourceNotFoundException("ResponseProposal", "id", proposalId));

        if (proposal.getStatus() != ProposalStatus.PENDING_APPROVAL) {
            throw new InvalidActionException("Proposal is not pending approval. Current status: " + proposal.getStatus());
        }

        if (proposal.getExpiresAt() != null && Instant.now().isAfter(proposal.getExpiresAt())) {
            proposal.setStatus(ProposalStatus.EXPIRED);
            proposalRepository.save(proposal);
            throw new InvalidActionException("Proposal has expired and cannot be approved.");
        }

        // Validate Separation of Duties (proposer != approver for HIGH/CRITICAL actions)
        if (!policyEngine.canApprove(proposal, approver)) {
            throw new InvalidActionException("Separation of Duties violation: Proposer cannot self-approve high-risk proposals.");
        }

        proposal.setStatus(ProposalStatus.APPROVED);
        proposal.setApprover(approver);
        proposal.setApprovedAt(Instant.now());
        proposal.setUpdatedAt(Instant.now());

        if (auditService != null) {
            auditService.recordEvent(approver, "RESPONSE_PROPOSAL_APPROVED", "ResponseProposal", proposal.getProposalUuid(), null,
                    "Reason: " + (request != null ? request.getReason() : "Approved by analyst"));
        }

        ResponseProposalRecord saved = proposalRepository.save(proposal);

        // If immediate execution requested, dispatch automatically
        if (request != null && request.isExecuteImmediately()) {
            return executeProposal(saved.getId(), approver);
        }

        return toDto(saved);
    }

    @Transactional
    public ResponseProposalDto denyProposal(Long proposalId, String denialReason, String denier) {
        ResponseProposalRecord proposal = proposalRepository.findById(proposalId)
                .orElseThrow(() -> new ResourceNotFoundException("ResponseProposal", "id", proposalId));

        if (proposal.getStatus() != ProposalStatus.PENDING_APPROVAL) {
            throw new InvalidActionException("Proposal is not pending approval. Current status: " + proposal.getStatus());
        }

        proposal.setStatus(ProposalStatus.DENIED);
        proposal.setApprover(denier);
        proposal.setDenialReason(denialReason != null ? denialReason : "Denied by analyst");
        proposal.setUpdatedAt(Instant.now());

        if (auditService != null) {
            auditService.recordEvent(denier, "RESPONSE_PROPOSAL_DENIED", "ResponseProposal", proposal.getProposalUuid(), null,
                    "Reason: " + proposal.getDenialReason());
        }

        return toDto(proposalRepository.save(proposal));
    }

    @Transactional
    public ResponseProposalDto cancelProposal(Long proposalId, String reason, String actor) {
        ResponseProposalRecord proposal = proposalRepository.findById(proposalId)
                .orElseThrow(() -> new ResourceNotFoundException("ResponseProposal", "id", proposalId));

        if (proposal.getStatus() == ProposalStatus.EXECUTED
                || proposal.getStatus() == ProposalStatus.SIMULATED
                || proposal.getStatus() == ProposalStatus.VERIFIED) {
            throw new InvalidActionException("Cannot cancel an action that has already completed execution.");
        }

        proposal.setStatus(ProposalStatus.CANCELLED);
        proposal.setDenialReason("Cancelled by " + actor + ": " + reason);
        proposal.setUpdatedAt(Instant.now());

        if (auditService != null) {
            auditService.recordEvent(actor, "RESPONSE_PROPOSAL_CANCELLED", "ResponseProposal", proposal.getProposalUuid(), null,
                    "Reason: " + reason);
        }

        return toDto(proposalRepository.save(proposal));
    }

    // --- Execution Dispatch & Verification ---

    @Transactional
    public ResponseProposalDto executeProposal(Long proposalId, String actor) {
        ResponseProposalRecord proposal = proposalRepository.findById(proposalId)
                .orElseThrow(() -> new ResourceNotFoundException("ResponseProposal", "id", proposalId));

        // State validation
        if (proposal.getStatus() != ProposalStatus.READY && proposal.getStatus() != ProposalStatus.APPROVED) {
            throw new InvalidActionException("Cannot execute proposal in state: " + proposal.getStatus());
        }

        if (proposal.getExpiresAt() != null && Instant.now().isAfter(proposal.getExpiresAt())) {
            proposal.setStatus(ProposalStatus.EXPIRED);
            proposalRepository.save(proposal);
            throw new InvalidActionException("Proposal has expired.");
        }

        // Concurrency / Idempotency lock
        String lockKey = proposal.getProposalUuid();
        if (!activeExecutionLocks.add(lockKey)) {
            throw new InvalidActionException("Proposal is currently undergoing execution dispatch.");
        }

        try {
            proposal.setStatus(ProposalStatus.EXECUTING);
            proposalRepository.save(proposal);

            // Locate appropriate adapter (defaults to SimulationResponseAdapter)
            ResponseAdapter adapter = responseAdapters.stream()
                    .filter(a -> a.supports(proposal))
                    .findFirst()
                    .orElseThrow(() -> new InvalidActionException("No supported response adapter for proposal mode: " + proposal.getExecutionMode()));

            ResponseExecutionResult result = adapter.dispatch(proposal);

            if (result.isSuccess()) {
                proposal.setStatus(ProposalStatus.EXECUTED);
            } else {
                proposal.setStatus(ProposalStatus.EXECUTION_FAILED);
            }
            proposal.setUpdatedAt(Instant.now());
            proposalRepository.save(proposal);

            if (auditService != null) {
                auditService.recordEvent(actor, "RESPONSE_ACTION_EXECUTED", "ResponseProposal", proposal.getProposalUuid(), null,
                        String.format("Result: %s, Duration: %dms, Message: %s",
                                result.isSuccess() ? "SUCCESS" : "FAILED", result.getDurationMs(), result.getMessage()));
            }

            // Record Outcome & Independent Verification (M6.10) without fabricating claims
            ResponseVerificationRecord verification = verificationEngine.verifyOutcome(proposal, result);
            if (!result.isSuccess() || verification.getStatus() == VerificationStatus.FAILED) {
                proposal.setStatus(ProposalStatus.EXECUTION_FAILED);
            } else if (verification.getStatus() == VerificationStatus.SIMULATION_ONLY) {
                proposal.setStatus(ProposalStatus.SIMULATED);
            } else if (verification.getStatus() == VerificationStatus.VERIFIED) {
                proposal.setStatus(ProposalStatus.VERIFIED);
            } else if (verification.getStatus() == VerificationStatus.UNAVAILABLE
                    || verification.getStatus() == VerificationStatus.INCONCLUSIVE) {
                proposal.setStatus(ProposalStatus.EXECUTED);
            } else {
                proposal.setStatus(ProposalStatus.VERIFICATION_FAILED);
            }
            ResponseProposalRecord finalSaved = proposalRepository.save(proposal);

            ResponseProposalDto dto = toDto(finalSaved);
            dto.setVerification(new ResponseVerificationDto(verification));
            return dto;
        } finally {
            activeExecutionLocks.remove(lockKey);
        }
    }

    // --- Querying Proposals ---

    @Transactional(readOnly = true)
    public List<ResponseProposalDto> getProposalsByIncident(Long incidentId) {
        return proposalRepository.findByIncidentIdOrderByProposedAtDesc(incidentId).stream()
                .map(this::toDto)
                .toList();
    }

    @Transactional(readOnly = true)
    public Page<ResponseProposalDto> getAllProposals(Pageable pageable) {
        return proposalRepository.findAllByOrderByProposedAtDesc(pageable)
                .map(this::toDto);
    }

    @Transactional(readOnly = true)
    public Page<ResponseProposalDto> getProposalsByStatus(ProposalStatus status, Pageable pageable) {
        return proposalRepository.findByStatusOrderByProposedAtDesc(status, pageable)
                .map(this::toDto);
    }

    @Transactional(readOnly = true)
    public ResponseProposalDto getProposalById(Long id) {
        ResponseProposalRecord proposal = proposalRepository.findById(id)
                .orElseThrow(() -> new ResourceNotFoundException("ResponseProposal", "id", id));
        return toDto(proposal);
    }

    @Transactional(readOnly = true)
    public Optional<ResponseVerificationDto> getLatestVerification(Long proposalId) {
        return verificationRepository.findTopByProposalIdOrderByVerifiedAtDesc(proposalId)
                .map(ResponseVerificationDto::new);
    }

    private ResponseProposalDto toDto(ResponseProposalRecord record) {
        ResponseProposalDto dto = new ResponseProposalDto(record);
        verificationRepository.findTopByProposalIdOrderByVerifiedAtDesc(record.getId())
                .ifPresent(v -> dto.setVerification(new ResponseVerificationDto(v)));
        return dto;
    }
}
