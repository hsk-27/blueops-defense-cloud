package com.blueops.response;

import jakarta.persistence.*;
import java.time.Instant;

@Entity
@Table(name = "response_targets")
public class ResponseTargetRecord {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "target_id", nullable = false, unique = true, length = 64)
    private String targetId;

    @Column(name = "target_type", nullable = false, length = 32)
    private String targetType;

    @Column(nullable = false, length = 128)
    private String identifier;

    @Column(name = "display_name", length = 128)
    private String displayName;

    @Column(nullable = false, length = 32)
    private String criticality = "STANDARD";

    @Column(nullable = false, length = 32)
    private String environment = "SYNTHETIC_TEST";

    @Column(name = "trust_status", nullable = false, length = 32)
    private String trustStatus = "AUTHORIZED";

    @Column(name = "is_protected", nullable = false)
    private boolean isProtected = false;

    @Column(name = "created_at", nullable = false, updatable = false)
    private Instant createdAt = Instant.now();

    public ResponseTargetRecord() {}

    public Long getId() { return id; }
    public void setId(Long id) { this.id = id; }

    public String getTargetId() { return targetId; }
    public void setTargetId(String targetId) { this.targetId = targetId; }

    public String getTargetType() { return targetType; }
    public void setTargetType(String targetType) { this.targetType = targetType; }

    public String getIdentifier() { return identifier; }
    public void setIdentifier(String identifier) { this.identifier = identifier; }

    public String getDisplayName() { return displayName; }
    public void setDisplayName(String displayName) { this.displayName = displayName; }

    public String getCriticality() { return criticality; }
    public void setCriticality(String criticality) { this.criticality = criticality; }

    public String getEnvironment() { return environment; }
    public void setEnvironment(String environment) { this.environment = environment; }

    public String getTrustStatus() { return trustStatus; }
    public void setTrustStatus(String trustStatus) { this.trustStatus = trustStatus; }

    public boolean isProtected() { return isProtected; }
    public void setProtected(boolean aProtected) { isProtected = aProtected; }

    public Instant getCreatedAt() { return createdAt; }
    public void setCreatedAt(Instant createdAt) { this.createdAt = createdAt; }
}
