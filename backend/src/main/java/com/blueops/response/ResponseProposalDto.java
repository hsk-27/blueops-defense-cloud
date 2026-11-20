package com.blueops.response;

import java.time.Instant;

public class ResponseProposalDto {
    private Long id;
    private String proposalUuid;
    private Long incidentId;
    private String findingId;
    private Long correlationId;
    private String actionCode;
    private String actionName;
    private String actionType;
    private String targetCanonicalId;
    private String targetIdentifier;
    private String targetType;
    private String parametersJson;
    private String proposedBy;
    private Instant proposedAt;
    private String riskLevel;
    private String executionMode;
    private String policyOutcome;
    private String policyReason;
    private String status;
    private boolean requiresApproval;
    private String approver;
    private Instant approvedAt;
    private String denialReason;
    private Instant expiresAt;
    private Long executionId;
    private Instant createdAt;
    private Instant updatedAt;
    private ResponseVerificationDto verification;

    public ResponseProposalDto() {}

    public ResponseProposalDto(ResponseProposalRecord record) {
        this.id = record.getId();
        this.proposalUuid = record.getProposalUuid();
        if (record.getIncident() != null) {
            this.incidentId = record.getIncident().getId();
        }
        this.findingId = record.getFindingId();
        this.correlationId = record.getCorrelationId();
        this.actionCode = record.getActionCode();
        this.actionName = record.getActionName();
        this.actionType = record.getActionType();
        this.targetCanonicalId = record.getTargetCanonicalId();
        this.targetIdentifier = record.getTargetIdentifier();
        this.targetType = record.getTargetType();
        this.parametersJson = record.getParametersJson();
        this.proposedBy = record.getProposedBy();
        this.proposedAt = record.getProposedAt();
        this.riskLevel = record.getRiskLevel() != null ? record.getRiskLevel().name() : "MODERATE";
        this.executionMode = record.getExecutionMode() != null ? record.getExecutionMode().name() : "SIMULATION";
        this.policyOutcome = record.getPolicyOutcome() != null ? record.getPolicyOutcome().name() : "REQUIRE_APPROVAL";
        this.policyReason = record.getPolicyReason();
        this.status = record.getStatus() != null ? record.getStatus().name() : "DRAFT";
        this.requiresApproval = record.isRequiresApproval();
        this.approver = record.getApprover();
        this.approvedAt = record.getApprovedAt();
        this.denialReason = record.getDenialReason();
        this.expiresAt = record.getExpiresAt();
        this.executionId = record.getExecutionId();
        this.createdAt = record.getCreatedAt();
        this.updatedAt = record.getUpdatedAt();
    }

    public Long getId() { return id; }
    public String getProposalUuid() { return proposalUuid; }
    public Long getIncidentId() { return incidentId; }
    public String getFindingId() { return findingId; }
    public Long getCorrelationId() { return correlationId; }
    public String getActionCode() { return actionCode; }
    public String getActionName() { return actionName; }
    public String getActionType() { return actionType; }
    public String getTargetCanonicalId() { return targetCanonicalId; }
    public String getTargetIdentifier() { return targetIdentifier; }
    public String getTargetType() { return targetType; }
    public String getParametersJson() { return parametersJson; }
    public String getProposedBy() { return proposedBy; }
    public Instant getProposedAt() { return proposedAt; }
    public String getRiskLevel() { return riskLevel; }
    public String getExecutionMode() { return executionMode; }
    public String getPolicyOutcome() { return policyOutcome; }
    public String getPolicyReason() { return policyReason; }
    public String getStatus() { return status; }
    public boolean isRequiresApproval() { return requiresApproval; }
    public String getApprover() { return approver; }
    public Instant getApprovedAt() { return approvedAt; }
    public String getDenialReason() { return denialReason; }
    public Instant getExpiresAt() { return expiresAt; }
    public Long getExecutionId() { return executionId; }
    public Instant getCreatedAt() { return createdAt; }
    public Instant getUpdatedAt() { return updatedAt; }
    public ResponseVerificationDto getVerification() { return verification; }
    public void setVerification(ResponseVerificationDto verification) { this.verification = verification; }
}
