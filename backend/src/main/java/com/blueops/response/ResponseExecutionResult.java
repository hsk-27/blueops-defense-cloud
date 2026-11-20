package com.blueops.response;

public class ResponseExecutionResult {
    private final boolean success;
    private final int statusCode;
    private final String mode;
    private final String message;
    private final String payload;
    private final long durationMs;

    public ResponseExecutionResult(boolean success, int statusCode, String mode, String message, String payload, long durationMs) {
        this.success = success;
        this.statusCode = statusCode;
        this.mode = mode;
        this.message = message;
        this.payload = payload;
        this.durationMs = durationMs;
    }

    public boolean isSuccess() { return success; }
    public int getStatusCode() { return statusCode; }
    public String getMode() { return mode; }
    public String getMessage() { return message; }
    public String getPayload() { return payload; }
    public long getDurationMs() { return durationMs; }
}
