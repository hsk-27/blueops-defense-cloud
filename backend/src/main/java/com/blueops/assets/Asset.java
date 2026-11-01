package com.blueops.assets;

import jakarta.persistence.*;
import java.time.Instant;

@Entity
@Table(name = "assets")
public class Asset {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "persistent_id", nullable = false, unique = true, length = 64)
    private String persistentId;

    @Column(nullable = false, length = 128)
    private String hostname;

    @Column(name = "ip_address", nullable = false, length = 64)
    private String ipAddress;

    @Column(name = "os_name", nullable = false, length = 64)
    private String osName;

    @Column(name = "os_version", length = 64)
    private String osVersion;

    @Column(nullable = false, length = 32)
    private String environment = "LAB";

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 32)
    private AssetStatus status = AssetStatus.HEALTHY;

    @Column(nullable = false, length = 32)
    private String criticality = "MEDIUM";

    @Column(name = "last_telemetry_at")
    private Instant lastTelemetryAt;

    @Column(name = "created_at", nullable = false, updatable = false)
    private Instant createdAt = Instant.now();

    @Column(name = "updated_at", nullable = false)
    private Instant updatedAt = Instant.now();

    public Asset() {}

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
