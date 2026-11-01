package com.blueops.assets;

import jakarta.validation.constraints.NotBlank;
import java.time.Instant;

public class AssetDto {
    private Long id;

    @NotBlank(message = "Persistent ID is required")
    private String persistentId;

    @NotBlank(message = "Hostname is required")
    private String hostname;

    @NotBlank(message = "IP address is required")
    private String ipAddress;

    @NotBlank(message = "OS name is required")
    private String osName;

    private String osVersion;
    private String environment;
    private AssetStatus status;
    private String criticality;
    private Instant lastTelemetryAt;
    private Instant createdAt;
    private Instant updatedAt;

    public AssetDto() {}

    public AssetDto(Asset asset) {
        this.id = asset.getId();
        this.persistentId = asset.getPersistentId();
        this.hostname = asset.getHostname();
        this.ipAddress = asset.getIpAddress();
        this.osName = asset.getOsName();
        this.osVersion = asset.getOsVersion();
        this.environment = asset.getEnvironment();
        this.status = asset.getStatus();
        this.criticality = asset.getCriticality();
        this.lastTelemetryAt = asset.getLastTelemetryAt();
        this.createdAt = asset.getCreatedAt();
        this.updatedAt = asset.getUpdatedAt();
    }

    public Long getId() { return id; }
    public void setId(Long id) { this.id = id; }

    public String getPersistentId() { return persistentId; }
    public void setPersistentId(String persistentId) { this.persistentId = persistentId; }

    public String getHostname() { return hostname; }
    public void setHostname(String hostname) { this.hostname = hostname; }

    public String getIpAddress() { return ipAddress; }
    public void setIpAddress(String ipAddress) { this.ipAddress = ipAddress; }

    public String getOsName() { return osName; }
    public void setOsName(String osName) { this.osName = osName; }

    public String getOsVersion() { return osVersion; }
    public void setOsVersion(String osVersion) { this.osVersion = osVersion; }

    public String getEnvironment() { return environment; }
    public void setEnvironment(String environment) { this.environment = environment; }

    public AssetStatus getStatus() { return status; }
    public void setStatus(AssetStatus status) { this.status = status; }

    public String getCriticality() { return criticality; }
    public void setCriticality(String criticality) { this.criticality = criticality; }

    public Instant getLastTelemetryAt() { return lastTelemetryAt; }
    public void setLastTelemetryAt(Instant lastTelemetryAt) { this.lastTelemetryAt = lastTelemetryAt; }

    public Instant getCreatedAt() { return createdAt; }
    public void setCreatedAt(Instant createdAt) { this.createdAt = createdAt; }

    public Instant getUpdatedAt() { return updatedAt; }
    public void setUpdatedAt(Instant updatedAt) { this.updatedAt = updatedAt; }
}
