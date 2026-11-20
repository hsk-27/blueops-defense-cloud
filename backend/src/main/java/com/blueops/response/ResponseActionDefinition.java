package com.blueops.response;

import jakarta.persistence.*;
import java.time.Instant;

@Entity
@Table(name = "response_action_catalog")
public class ResponseActionDefinition {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "action_code", nullable = false, unique = true, length = 32)
    private String actionCode;

    @Column(nullable = false, length = 128)
    private String name;

    @Column(nullable = false, columnDefinition = "TEXT")
    private String description;

    @Column(nullable = false, length = 64)
    private String category;

    @Column(name = "target_type", nullable = false, length = 32)
    private String targetType;

    @Enumerated(EnumType.STRING)
    @Column(name = "risk_level", nullable = false, length = 32)
    private ResponseRiskLevel riskLevel;

    @Column(name = "requires_approval", nullable = false)
    private boolean requiresApproval = true;

    @Column(name = "simulation_supported", nullable = false)
    private boolean simulationSupported = true;

    @Column(name = "rollback_supported", nullable = false)
    private boolean rollbackSupported = true;

    @Column(name = "reversal_action_code", length = 32)
    private String reversalActionCode;

    @Column(name = "timeout_seconds", nullable = false)
    private int timeoutSeconds = 30;

    @Column(name = "verification_method", nullable = false, length = 64)
    private String verificationMethod = "STATE_QUERY";

    @Column(name = "parameter_schema", columnDefinition = "TEXT")
    private String parameterSchema;

    @Column(name = "is_enabled", nullable = false)
    private boolean isEnabled = true;

    @Column(name = "created_at", nullable = false, updatable = false)
    private Instant createdAt = Instant.now();

    public ResponseActionDefinition() {}

    public Long getId() { return id; }
    public void setId(Long id) { this.id = id; }

    public String getActionCode() { return actionCode; }
    public void setActionCode(String actionCode) { this.actionCode = actionCode; }

    public String getName() { return name; }
    public void setName(String name) { this.name = name; }

    public String getDescription() { return description; }
    public void setDescription(String description) { this.description = description; }

    public String getCategory() { return category; }
    public void setCategory(String category) { this.category = category; }

    public String getTargetType() { return targetType; }
    public void setTargetType(String targetType) { this.targetType = targetType; }

    public ResponseRiskLevel getRiskLevel() { return riskLevel; }
    public void setRiskLevel(ResponseRiskLevel riskLevel) { this.riskLevel = riskLevel; }

    public boolean isRequiresApproval() { return requiresApproval; }
    public void setRequiresApproval(boolean requiresApproval) { this.requiresApproval = requiresApproval; }

    public boolean isSimulationSupported() { return simulationSupported; }
    public void setSimulationSupported(boolean simulationSupported) { this.simulationSupported = simulationSupported; }

    public boolean isRollbackSupported() { return rollbackSupported; }
    public void setRollbackSupported(boolean rollbackSupported) { this.rollbackSupported = rollbackSupported; }

    public String getReversalActionCode() { return reversalActionCode; }
    public void setReversalActionCode(String reversalActionCode) { this.reversalActionCode = reversalActionCode; }

    public int getTimeoutSeconds() { return timeoutSeconds; }
    public void setTimeoutSeconds(int timeoutSeconds) { this.timeoutSeconds = timeoutSeconds; }

    public String getVerificationMethod() { return verificationMethod; }
    public void setVerificationMethod(String verificationMethod) { this.verificationMethod = verificationMethod; }

    public String getParameterSchema() { return parameterSchema; }
    public void setParameterSchema(String parameterSchema) { this.parameterSchema = parameterSchema; }

    public boolean isEnabled() { return isEnabled; }
    public void setEnabled(boolean enabled) { isEnabled = enabled; }

    public Instant getCreatedAt() { return createdAt; }
    public void setCreatedAt(Instant createdAt) { this.createdAt = createdAt; }
}
