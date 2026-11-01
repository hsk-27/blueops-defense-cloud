package com.blueops.response;

import java.time.Instant;

public class ResponseExecutionDto {
    private Long id;
    private Long actionId;
    private String actionUuid;
    private Instant executedAt;
    private Long executionDurationMs;
    private boolean success;
    private Integer statusCode;
    private String responsePayload;
    private String errorMessage;
    private boolean verificationPassed;

    public ResponseExecutionDto() {}

    public ResponseExecutionDto(ResponseExecution exec) {
        this.id = exec.getId();
        this.actionId = exec.getAction().getId();
        this.actionUuid = exec.getAction().getActionUuid();
        this.executedAt = exec.getExecutedAt();
        this.executionDurationMs = exec.getExecutionDurationMs();
        this.success = exec.isSuccess();
        this.statusCode = exec.getStatusCode();
        this.responsePayload = exec.getResponsePayload();
        this.errorMessage = exec.getErrorMessage();
        this.verificationPassed = exec.isVerificationPassed();
    }

    public Long getId() { return id; }
    public void setId(Long id) { this.id = id; }

    public Long getActionId() { return actionId; }
    public void setActionId(Long actionId) { this.actionId = actionId; }

    public String getActionUuid() { return actionUuid; }
    public void setActionUuid(String actionUuid) { this.actionUuid = actionUuid; }

    public Instant getExecutedAt() { return executedAt; }
    public void setExecutedAt(Instant executedAt) { this.executedAt = executedAt; }

    public Long getExecutionDurationMs() { return executionDurationMs; }
    public void setExecutionDurationMs(Long executionDurationMs) { this.executionDurationMs = executionDurationMs; }

    public boolean isSuccess() { return success; }
    public void setSuccess(boolean success) { this.success = success; }

    public Integer getStatusCode() { return statusCode; }
    public void setStatusCode(Integer statusCode) { this.statusCode = statusCode; }

    public String getResponsePayload() { return responsePayload; }
    public void setResponsePayload(String responsePayload) { this.responsePayload = responsePayload; }

    public String getErrorMessage() { return errorMessage; }
    public void setErrorMessage(String errorMessage) { this.errorMessage = errorMessage; }

    public boolean isVerificationPassed() { return verificationPassed; }
    public void setVerificationPassed(boolean verificationPassed) { this.verificationPassed = verificationPassed; }
}
