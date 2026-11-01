package com.blueops.response;

import jakarta.persistence.*;
import java.time.Instant;

@Entity
@Table(name = "response_executions")
public class ResponseExecution {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "action_id", nullable = false)
    private ResponseAction action;

    @Column(name = "executed_at", nullable = false)
    private Instant executedAt = Instant.now();

    @Column(name = "execution_duration_ms", nullable = false)
    private Long executionDurationMs;

    @Column(nullable = false)
    private boolean success;

    @Column(name = "status_code")
    private Integer statusCode;

    @Column(name = "response_payload", columnDefinition = "TEXT")
    private String responsePayload;

    @Column(name = "error_message", columnDefinition = "TEXT")
    private String errorMessage;

    @Column(name = "verification_passed", nullable = false)
    private boolean verificationPassed = false;

    public ResponseExecution() {}

    public Long getId() { return id; }
    public void setId(Long id) { this.id = id; }

    public ResponseAction getAction() { return action; }
    public void setAction(ResponseAction action) { this.action = action; }

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
