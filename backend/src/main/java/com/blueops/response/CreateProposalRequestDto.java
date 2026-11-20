package com.blueops.response;

import java.util.Map;

public class CreateProposalRequestDto {
    private Long incidentId;
    private String findingId;
    private Long correlationId;
    private String actionCode;
    private String targetIdentifier;
    private String targetCanonicalId;
    private ResponseExecutionMode executionMode = ResponseExecutionMode.SIMULATION;
    private Map<String, Object> parameters;

    public CreateProposalRequestDto() {}

    public Long getIncidentId() { return incidentId; }
    public void setIncidentId(Long incidentId) { this.incidentId = incidentId; }

    public String getFindingId() { return findingId; }
    public void setFindingId(String findingId) { this.findingId = findingId; }

    public Long getCorrelationId() { return correlationId; }
    public void setCorrelationId(Long correlationId) { this.correlationId = correlationId; }

    public String getActionCode() { return actionCode; }
    public void setActionCode(String actionCode) { this.actionCode = actionCode; }

    public String getTargetIdentifier() { return targetIdentifier; }
    public void setTargetIdentifier(String targetIdentifier) { this.targetIdentifier = targetIdentifier; }

    public String getTargetCanonicalId() { return targetCanonicalId; }
    public void setTargetCanonicalId(String targetCanonicalId) { this.targetCanonicalId = targetCanonicalId; }

    public ResponseExecutionMode getExecutionMode() { return executionMode; }
    public void setExecutionMode(ResponseExecutionMode executionMode) { this.executionMode = executionMode; }

    public Map<String, Object> getParameters() { return parameters; }
    public void setParameters(Map<String, Object> parameters) { this.parameters = parameters; }
}
