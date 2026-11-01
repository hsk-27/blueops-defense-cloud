package com.blueops.response;

import java.time.Instant;

public class ResponseActionDto {
    private Long id;
    private String actionUuid;
    private String playbookCode;
    private Long incidentId;
    private String targetIdentifier;
    private Long targetAssetId;
    private String requestedBy;
    private String approvalStatus;
    private String approvedBy;
    private Instant approvedAt;
    private String executionStatus;
    private boolean isSimulation;
    private Long reversalActionId;
    private Instant createdAt;
    private Instant updatedAt;

    public ResponseActionDto() {}

    public ResponseActionDto(ResponseAction action) {
        this.id = action.getId();
        this.actionUuid = action.getActionUuid();
        this.playbookCode = action.getPlaybookCode();
        if (action.getIncident() != null) {
            this.incidentId = action.getIncident().getId();
        }
        this.targetIdentifier = action.getTargetIdentifier();
        if (action.getTargetAsset() != null) {
            this.targetAssetId = action.getTargetAsset().getId();
        }
        this.requestedBy = action.getRequestedBy();
        this.approvalStatus = action.getApprovalStatus();
        this.approvedBy = action.getApprovedBy();
        this.approvedAt = action.getApprovedAt();
        this.executionStatus = action.getExecutionStatus();
        this.isSimulation = action.isSimulation();
        if (action.getReversalAction() != null) {
            this.reversalActionId = action.getReversalAction().getId();
        }
        this.createdAt = action.getCreatedAt();
        this.updatedAt = action.getUpdatedAt();
    }

    public Long getId() { return id; }
    public void setId(Long id) { this.id = id; }

    public String getActionUuid() { return actionUuid; }
    public void setActionUuid(String actionUuid) { this.actionUuid = actionUuid; }

    public String getPlaybookCode() { return playbookCode; }
    public void setPlaybookCode(String playbookCode) { this.playbookCode = playbookCode; }

    public Long getIncidentId() { return incidentId; }
    public void setIncidentId(Long incidentId) { this.incidentId = incidentId; }

    public String getTargetIdentifier() { return targetIdentifier; }
    public void setTargetIdentifier(String targetIdentifier) { this.targetIdentifier = targetIdentifier; }

    public Long getTargetAssetId() { return targetAssetId; }
    public void setTargetAssetId(Long targetAssetId) { this.targetAssetId = targetAssetId; }

    public String getRequestedBy() { return requestedBy; }
    public void setRequestedBy(String requestedBy) { this.requestedBy = requestedBy; }

    public String getApprovalStatus() { return approvalStatus; }
    public void setApprovalStatus(String approvalStatus) { this.approvalStatus = approvalStatus; }

    public String getApprovedBy() { return approvedBy; }
    public void setApprovedBy(String approvedBy) { this.approvedBy = approvedBy; }

    public Instant getApprovedAt() { return approvedAt; }
    public void setApprovedAt(Instant approvedAt) { this.approvedAt = approvedAt; }

    public String getExecutionStatus() { return executionStatus; }
    public void setExecutionStatus(String executionStatus) { this.executionStatus = executionStatus; }

    public boolean isSimulation() { return isSimulation; }
    public void setSimulation(boolean simulation) { isSimulation = simulation; }

    public Long getReversalActionId() { return reversalActionId; }
    public void setReversalActionId(Long reversalActionId) { this.reversalActionId = reversalActionId; }

    public Instant getCreatedAt() { return createdAt; }
    public void setCreatedAt(Instant createdAt) { this.createdAt = createdAt; }

    public Instant getUpdatedAt() { return updatedAt; }
    public void setUpdatedAt(Instant updatedAt) { this.updatedAt = updatedAt; }
}
