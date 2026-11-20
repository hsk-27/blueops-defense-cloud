package com.blueops.response;

public class ApproveProposalRequestDto {
    private String reason;
    private boolean executeImmediately = true;

    public ApproveProposalRequestDto() {}

    public ApproveProposalRequestDto(String reason, boolean executeImmediately) {
        this.reason = reason;
        this.executeImmediately = executeImmediately;
    }

    public String getReason() { return reason; }
    public void setReason(String reason) { this.reason = reason; }

    public boolean isExecuteImmediately() { return executeImmediately; }
    public void setExecuteImmediately(boolean executeImmediately) { this.executeImmediately = executeImmediately; }
}
