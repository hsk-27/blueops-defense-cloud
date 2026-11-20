package com.blueops.entities;

import java.time.Instant;
import java.util.Map;

public class EntityDto {
    private Long id;
    private String canonicalId;
    private EntityType entityType;
    private String displayName;
    private Map<String, Object> attributes;
    private double riskScore;
    private EntityStatus status;
    private long observationCount;
    private Instant firstSeen;
    private Instant lastSeen;
    private Instant createdAt;

    public EntityDto() {}

    public EntityDto(Long id, String canonicalId, EntityType entityType, String displayName,
                     Map<String, Object> attributes, double riskScore, EntityStatus status,
                     long observationCount, Instant firstSeen, Instant lastSeen, Instant createdAt) {
        this.id = id;
        this.canonicalId = canonicalId;
        this.entityType = entityType;
        this.displayName = displayName;
        this.attributes = attributes;
        this.riskScore = riskScore;
        this.status = status;
        this.observationCount = observationCount;
        this.firstSeen = firstSeen;
        this.lastSeen = lastSeen;
        this.createdAt = createdAt;
    }

    public Long getId() { return id; }
    public void setId(Long id) { this.id = id; }

    public String getCanonicalId() { return canonicalId; }
    public void setCanonicalId(String canonicalId) { this.canonicalId = canonicalId; }

    public EntityType getEntityType() { return entityType; }
    public void setEntityType(EntityType entityType) { this.entityType = entityType; }

    public String getDisplayName() { return displayName; }
    public void setDisplayName(String displayName) { this.displayName = displayName; }

    public Map<String, Object> getAttributes() { return attributes; }
    public void setAttributes(Map<String, Object> attributes) { this.attributes = attributes; }

    public double getRiskScore() { return riskScore; }
    public void setRiskScore(double riskScore) { this.riskScore = riskScore; }

    public EntityStatus getStatus() { return status; }
    public void setStatus(EntityStatus status) { this.status = status; }

    public long getObservationCount() { return observationCount; }
    public void setObservationCount(long observationCount) { this.observationCount = observationCount; }

    public Instant getFirstSeen() { return firstSeen; }
    public void setFirstSeen(Instant firstSeen) { this.firstSeen = firstSeen; }

    public Instant getLastSeen() { return lastSeen; }
    public void setLastSeen(Instant lastSeen) { this.lastSeen = lastSeen; }

    public Instant getCreatedAt() { return createdAt; }
    public void setCreatedAt(Instant createdAt) { this.createdAt = createdAt; }
}
