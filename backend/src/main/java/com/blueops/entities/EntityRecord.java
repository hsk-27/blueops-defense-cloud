package com.blueops.entities;

import jakarta.persistence.*;
import java.time.Instant;

@Entity
@Table(name = "entities")
public class EntityRecord {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "canonical_id", nullable = false, unique = true, length = 255)
    private String canonicalId;

    @Enumerated(EnumType.STRING)
    @Column(name = "entity_type", nullable = false, length = 32)
    private EntityType entityType;

    @Column(name = "display_name", nullable = false, length = 255)
    private String displayName;

    @Column(name = "attributes_json", columnDefinition = "TEXT")
    private String attributesJson;

    @Column(name = "risk_score", nullable = false)
    private double riskScore = 0.0;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 32)
    private EntityStatus status = EntityStatus.ACTIVE;

    @Column(name = "observation_count", nullable = false)
    private long observationCount = 1;

    @Column(name = "first_seen", nullable = false)
    private Instant firstSeen = Instant.now();

    @Column(name = "last_seen", nullable = false)
    private Instant lastSeen = Instant.now();

    @Column(name = "created_at", nullable = false, updatable = false)
    private Instant createdAt = Instant.now();

    @Column(name = "updated_at", nullable = false)
    private Instant updatedAt = Instant.now();

    public EntityRecord() {}

    public EntityRecord(String canonicalId, EntityType entityType, String displayName) {
        this.canonicalId = canonicalId;
        this.entityType = entityType;
        this.displayName = displayName;
        this.firstSeen = Instant.now();
        this.lastSeen = Instant.now();
        this.createdAt = Instant.now();
        this.updatedAt = Instant.now();
    }

    public Long getId() { return id; }
    public void setId(Long id) { this.id = id; }

    public String getCanonicalId() { return canonicalId; }
    public void setCanonicalId(String canonicalId) { this.canonicalId = canonicalId; }

    public EntityType getEntityType() { return entityType; }
    public void setEntityType(EntityType entityType) { this.entityType = entityType; }

    public String getDisplayName() { return displayName; }
    public void setDisplayName(String displayName) { this.displayName = displayName; }

    public String getAttributesJson() { return attributesJson; }
    public void setAttributesJson(String attributesJson) { this.attributesJson = attributesJson; }

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

    public Instant getUpdatedAt() { return updatedAt; }
    public void setUpdatedAt(Instant updatedAt) { this.updatedAt = updatedAt; }
}
