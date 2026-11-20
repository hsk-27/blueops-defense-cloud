package com.blueops.response;

import com.blueops.incidents.Incident;
import jakarta.persistence.*;
import java.time.Instant;

@Entity
@Table(name = "response_proposals")
public class ResponseProposalRecord {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "proposal_uuid", nullable = false, unique = true, length = 64)
    private String proposalUuid;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "incident_id")
    private Incident incident;

    @Column(name = "finding_id", length = 64)
    private String findingId;

    @Column(name = "correlation_id")
    private Long correlationId;

    @Column(name = "action_code", nullable = false, length = 32)
    private String actionCode;

    @Column(name = "action_name", nullable = false, length = 128)
    private String actionName;

    @Column(name = "action_type", nullable = false, length = 64)
    private String actionType;

    @Column(name = "target_canonical_id", length = 128)
    private String targetCanonicalId;

    @Column(name = "target_identifier", nullable = false, length = 128)
    private String targetIdentifier;

    @Column(name = "target_type", nullable = false, length = 32)
    private String targetType;

    @Column(name = "parameters_json", columnDefinition = "TEXT")
    private String parametersJson;

    @Column(name = "proposed_by", nullable = false, length = 64)
    private String proposedBy;

    @Column(name = "proposed_at", nullable = false)
    private Instant proposedAt = Instant.now();

    @Enumerated(EnumType.STRING)
    @Column(name = "risk_level", nullable = false, length = 32)
    private ResponseRiskLevel riskLevel;

    @Enumerated(EnumType.STRING)
    @Column(name = "execution_mode", nullable = false, length = 32)
    private ResponseExecutionMode executionMode = ResponseExecutionMode.SIMULATION;

    @Enumerated(EnumType.STRING)
    @Column(name = "policy_outcome", nullable = false, length = 32)
    private ResponsePolicyOutcome policyOutcome;

    @Column(name = "policy_reason", columnDefinition = "TEXT")
    private String policyReason;

    @Enumerated(EnumType.STRING)
    @Column(name = "status", nullable = false, length = 32)
    private ProposalStatus status = ProposalStatus.DRAFT;

    @Column(name = "requires_approval", nullable = false)
    private boolean requiresApproval = true;

    @Column(length = 64)
    private String approver;

    @Column(name = "approved_at")
    private Instant approvedAt;

    @Column(name = "denial_reason", columnDefinition = "TEXT")
    private String denialReason;

    @Column(name = "expires_at")
    private Instant expiresAt;

    @Column(name = "execution_id")
    private Long executionId;

    @Column(name = "created_at", nullable = false, updatable = false)
    private Instant createdAt = Instant.now();

    @Column(name = "updated_at", nullable = false)
    private Instant updatedAt = Instant.now();

    public ResponseProposalRecord() {}

    public Long getId() { return id; }
    public void setId(Long id) { this.id = id; }

    public String getProposalUuid() { return proposalUuid; }
    public void setProposalUuid(String proposalUuid) { this.proposalUuid = proposalUuid; }

    public Incident getIncident() { return incident; }
    public void setIncident(Incident incident) { this.incident = incident; }

    public String getFindingId() { return findingId; }
    public void setFindingId(String findingId) { this.findingId = findingId; }

    public Long getCorrelationId() { return correlationId; }
    public void setCorrelationId(Long correlationId) { this.correlationId = correlationId; }

    public String getActionCode() { return actionCode; }
    public void setActionCode(String actionCode) { this.actionCode = actionCode; }

    public String getActionName() { return actionName; }
    public void setActionName(String actionName) { this.actionName = actionName; }

    public String getActionType() { return actionType; }
    public void setActionType(String actionType) { this.actionType = actionType; }

    public String getTargetCanonicalId() { return targetCanonicalId; }
    public void setTargetCanonicalId(String targetCanonicalId) { this.targetCanonicalId = targetCanonicalId; }

    public String getTargetIdentifier() { return targetIdentifier; }
    public void setTargetIdentifier(String targetIdentifier) { this.targetIdentifier = targetIdentifier; }

    public String getTargetType() { return targetType; }
    public void setTargetType(String targetType) { this.targetType = targetType; }

    public String getParametersJson() { return parametersJson; }
    public void setParametersJson(String parametersJson) { this.parametersJson = parametersJson; }

    public String getProposedBy() { return proposedBy; }
    public void setProposedBy(String proposedBy) { this.proposedBy = proposedBy; }

    public Instant getProposedAt() { return proposedAt; }
    public void setProposedAt(Instant proposedAt) { this.proposedAt = proposedAt; }

    public ResponseRiskLevel getRiskLevel() { return riskLevel; }
    public void setRiskLevel(ResponseRiskLevel riskLevel) { this.riskLevel = riskLevel; }

    public ResponseExecutionMode getExecutionMode() { return executionMode; }
    public void setExecutionMode(ResponseExecutionMode executionMode) { this.executionMode = executionMode; }

    public ResponsePolicyOutcome getPolicyOutcome() { return policyOutcome; }
    public void setPolicyOutcome(ResponsePolicyOutcome policyOutcome) { this.policyOutcome = policyOutcome; }

    public String getPolicyReason() { return policyReason; }
    public void setPolicyReason(String policyReason) { this.policyReason = policyReason; }

    public ProposalStatus getStatus() { return status; }
    public void setStatus(ProposalStatus status) { this.status = status; }

    public boolean isRequiresApproval() { return requiresApproval; }
    public void setRequiresApproval(boolean requiresApproval) { this.requiresApproval = requiresApproval; }

    public String getApprover() { return approver; }
    public void setApprover(String approver) { this.approver = approver; }

    public Instant getApprovedAt() { return approvedAt; }
    public void setApprovedAt(Instant approvedAt) { this.approvedAt = approvedAt; }

    public String getDenialReason() { return denialReason; }
    public void setDenialReason(String denialReason) { this.denialReason = denialReason; }

    public Instant getExpiresAt() { return expiresAt; }
    public void setExpiresAt(Instant expiresAt) { this.expiresAt = expiresAt; }

    public Long getExecutionId() { return executionId; }
    public void setExecutionId(Long executionId) { this.executionId = executionId; }

    public Instant getCreatedAt() { return createdAt; }
    public void setCreatedAt(Instant createdAt) { this.createdAt = createdAt; }

    public Instant getUpdatedAt() { return updatedAt; }
    public void setUpdatedAt(Instant updatedAt) { this.updatedAt = updatedAt; }
}
