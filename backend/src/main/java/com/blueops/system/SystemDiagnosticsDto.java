package com.blueops.system;

import java.time.Instant;
import java.util.Map;

/**
 * Safe, sanitized system operational diagnostic data (M7 Stabilization).
 * Strictly contains NO secrets, tokens, credentials, or internal memory dumps.
 */
public class SystemDiagnosticsDto {

    private String status;
    private Instant timestamp;
    private long uptimeSeconds;
    private String uptimeFormatted;

    private Map<String, Object> memory;
    private Map<String, Object> telemetryPipeline;
    private Map<String, Object> detectionEngine;
    private Map<String, Object> responseEngine;
    private Map<String, Object> storageAndSearch;

    public SystemDiagnosticsDto() {
        this.timestamp = Instant.now();
    }

    public String getStatus() {
        return status;
    }

    public void setStatus(String status) {
        this.status = status;
    }

    public Instant getTimestamp() {
        return timestamp;
    }

    public void setTimestamp(Instant timestamp) {
        this.timestamp = timestamp;
    }

    public long getUptimeSeconds() {
        return uptimeSeconds;
    }

    public void setUptimeSeconds(long uptimeSeconds) {
        this.uptimeSeconds = uptimeSeconds;
    }

    public String getUptimeFormatted() {
        return uptimeFormatted;
    }

    public void setUptimeFormatted(String uptimeFormatted) {
        this.uptimeFormatted = uptimeFormatted;
    }

    public Map<String, Object> getMemory() {
        return memory;
    }

    public void setMemory(Map<String, Object> memory) {
        this.memory = memory;
    }

    public Map<String, Object> getTelemetryPipeline() {
        return telemetryPipeline;
    }

    public void setTelemetryPipeline(Map<String, Object> telemetryPipeline) {
        this.telemetryPipeline = telemetryPipeline;
    }

    public Map<String, Object> getDetectionEngine() {
        return detectionEngine;
    }

    public void setDetectionEngine(Map<String, Object> detectionEngine) {
        this.detectionEngine = detectionEngine;
    }

    public Map<String, Object> getResponseEngine() {
        return responseEngine;
    }

    public void setResponseEngine(Map<String, Object> responseEngine) {
        this.responseEngine = responseEngine;
    }

    public Map<String, Object> getStorageAndSearch() {
        return storageAndSearch;
    }

    public void setStorageAndSearch(Map<String, Object> storageAndSearch) {
        this.storageAndSearch = storageAndSearch;
    }
}
