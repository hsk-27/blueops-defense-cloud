package com.blueops.response;

import com.blueops.assets.Asset;
import com.blueops.incidents.Incident;
import jakarta.persistence.*;
import java.time.Instant;

@Entity
@Table(name = "response_actions")
public class ResponseAction {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "action_uuid", nullable = false, unique = true, length = 64)
    private String actionUuid;

    @Column(name = "playbook_code", nullable = false, length = 32)
    private String playbookCode;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "incident_id")
    private Incident incident;

    @Column(name = "target_identifier", nullable = false, length = 128)
    private String targetIdentifier; // IP, username, or hostname

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "target_asset_id")
    private Asset targetAsset;

    @Column(name = "requested_by", nullable = false, length = 64)
    private String requestedBy;

    @Column(name = "approval_status", nullable = false, length = 32)
    private String approvalStatus = "PENDING"; // PENDING, APPROVED, REJECTED, AUTO_APPROVED

    @Column(name = "approved_by", length = 64)
    private String approvedBy;

    @Column(name = "approved_at")
    private Instant approvedAt;

    @Column(name = "execution_status", nullable = false, length = 32)
    private String executionStatus = "NOT_STARTED"; // NOT_STARTED, IN_PROGRESS, SUCCEEDED, FAILED, ROLLED_BACK

    @Column(name = "is_simulation", nullable = false)
    private boolean isSimulation = true;

    @OneToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "reversal_action_id")
    private ResponseAction reversalAction;

    @Column(name = "created_at", nullable = false, updatable = false)
    private Instant createdAt = Instant.now();

    @Column(name = "updated_at", nullable = false)
    private Instant updatedAt = Instant.now();

    public ResponseAction() {}

    public Long getId() { return id; }
    public void setId(Long id) { this.id = id; }

    public String getActionUuid() { return actionUuid; }
    public void setActionUuid(String actionUuid) { this.actionUuid = actionUuid; }

    public String getPlaybookCode() { return playbookCode; }
    public void setPlaybookCode(String playbookCode) { this.playbookCode = playbookCode; }

    public Incident getIncident() { return incident; }
    public void setIncident(Incident incident) { this.incident = incident; }

    public String getTargetIdentifier() { return targetIdentifier; }
    public void setTargetIdentifier(String targetIdentifier) { this.targetIdentifier = targetIdentifier; }

    public Asset getTargetAsset() { return targetAsset; }
    public void setTargetAsset(Asset targetAsset) { this.targetAsset = targetAsset; }

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

    public ResponseAction getReversalAction() { return reversalAction; }
    public void setReversalAction(ResponseAction reversalAction) { this.reversalAction = reversalAction; }

    public Instant getCreatedAt() { return createdAt; }
    public void setCreatedAt(Instant createdAt) { this.createdAt = createdAt; }

    public Instant getUpdatedAt() { return updatedAt; }
    public void setUpdatedAt(Instant updatedAt) { this.updatedAt = updatedAt; }
}
