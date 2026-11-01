package com.blueops.response;

import jakarta.persistence.*;
import java.time.Instant;

@Entity
@Table(name = "response_playbooks")
public class ResponsePlaybook {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "playbook_code", nullable = false, unique = true, length = 32)
    private String playbookCode;

    @Column(nullable = false, length = 128)
    private String name;

    @Column(nullable = false, columnDefinition = "TEXT")
    private String description;

    @Column(name = "action_type", nullable = false, length = 64)
    private String actionType; // BLOCK_IP, DISABLE_USER, ISOLATE_HOST, RESTORE_IP, ENABLE_USER

    @Column(name = "requires_approval", nullable = false)
    private boolean requiresApproval = true;

    @Column(name = "target_type", nullable = false, length = 32)
    private String targetType; // IP, USERNAME, ASSET

    @Column(name = "rollback_supported", nullable = false)
    private boolean rollbackSupported = true;

    @Column(name = "created_at", nullable = false, updatable = false)
    private Instant createdAt = Instant.now();

    public ResponsePlaybook() {}

    public Long getId() { return id; }
    public void setId(Long id) { this.id = id; }

    public String getPlaybookCode() { return playbookCode; }
    public void setPlaybookCode(String playbookCode) { this.playbookCode = playbookCode; }

    public String getName() { return name; }
    public void setName(String name) { this.name = name; }

    public String getDescription() { return description; }
    public void setDescription(String description) { this.description = description; }

    public String getActionType() { return actionType; }
    public void setActionType(String actionType) { this.actionType = actionType; }

    public boolean isRequiresApproval() { return requiresApproval; }
    public void setRequiresApproval(boolean requiresApproval) { this.requiresApproval = requiresApproval; }

    public String getTargetType() { return targetType; }
    public void setTargetType(String targetType) { this.targetType = targetType; }

    public boolean isRollbackSupported() { return rollbackSupported; }
    public void setRollbackSupported(boolean rollbackSupported) { this.rollbackSupported = rollbackSupported; }

    public Instant getCreatedAt() { return createdAt; }
    public void setCreatedAt(Instant createdAt) { this.createdAt = createdAt; }
}
