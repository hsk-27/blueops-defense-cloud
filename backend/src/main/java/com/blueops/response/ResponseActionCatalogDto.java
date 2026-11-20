package com.blueops.response;

public class ResponseActionCatalogDto {
    private Long id;
    private String actionCode;
    private String name;
    private String description;
    private String category;
    private String targetType;
    private String riskLevel;
    private boolean requiresApproval;
    private boolean simulationSupported;
    private boolean rollbackSupported;
    private String reversalActionCode;
    private int timeoutSeconds;
    private String verificationMethod;
    private String parameterSchema;
    private boolean isEnabled;

    public ResponseActionCatalogDto() {}

    public ResponseActionCatalogDto(ResponseActionDefinition entity) {
        this.id = entity.getId();
        this.actionCode = entity.getActionCode();
        this.name = entity.getName();
        this.description = entity.getDescription();
        this.category = entity.getCategory();
        this.targetType = entity.getTargetType();
        this.riskLevel = entity.getRiskLevel() != null ? entity.getRiskLevel().name() : "MODERATE";
        this.requiresApproval = entity.isRequiresApproval();
        this.simulationSupported = entity.isSimulationSupported();
        this.rollbackSupported = entity.isRollbackSupported();
        this.reversalActionCode = entity.getReversalActionCode();
        this.timeoutSeconds = entity.getTimeoutSeconds();
        this.verificationMethod = entity.getVerificationMethod();
        this.parameterSchema = entity.getParameterSchema();
        this.isEnabled = entity.isEnabled();
    }

    public Long getId() { return id; }
    public String getActionCode() { return actionCode; }
    public String getName() { return name; }
    public String getDescription() { return description; }
    public String getCategory() { return category; }
    public String getTargetType() { return targetType; }
    public String getRiskLevel() { return riskLevel; }
    public boolean isRequiresApproval() { return requiresApproval; }
    public boolean isSimulationSupported() { return simulationSupported; }
    public boolean isRollbackSupported() { return rollbackSupported; }
    public String getReversalActionCode() { return reversalActionCode; }
    public int getTimeoutSeconds() { return timeoutSeconds; }
    public String getVerificationMethod() { return verificationMethod; }
    public String getParameterSchema() { return parameterSchema; }
    public boolean isEnabled() { return isEnabled; }
}
