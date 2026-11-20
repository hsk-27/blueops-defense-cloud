package com.blueops.entities;

import jakarta.persistence.*;
import java.time.Instant;

@Entity
@Table(name = "entity_observations")
public class EntityObservationRecord {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "entity_id", nullable = false)
    private Long entityId;

    @Column(name = "canonical_id", nullable = false, length = 255)
    private String canonicalId;

    @Column(name = "source_type", nullable = false, length = 64)
    private String sourceType;

    @Column(name = "source_id", length = 128)
    private String sourceId;

    @Column(name = "host_context", length = 128)
    private String hostContext;

    @Column(name = "raw_evidence_ref", length = 255)
    private String rawEvidenceRef;

    @Column(name = "observed_attributes_json", columnDefinition = "TEXT")
    private String observedAttributesJson;

    @Column(name = "confidence_score", nullable = false)
    private double confidenceScore = 1.0;

    @Column(name = "observed_at", nullable = false)
    private Instant observedAt = Instant.now();

    public EntityObservationRecord() {}

    public EntityObservationRecord(Long entityId, String canonicalId, String sourceType, String sourceId,
                                   String hostContext, String rawEvidenceRef, String observedAttributesJson,
                                   double confidenceScore, Instant observedAt) {
        this.entityId = entityId;
        this.canonicalId = canonicalId;
        this.sourceType = sourceType;
        this.sourceId = sourceId;
        this.hostContext = hostContext;
        this.rawEvidenceRef = rawEvidenceRef;
        this.observedAttributesJson = observedAttributesJson;
        this.confidenceScore = confidenceScore;
        this.observedAt = observedAt != null ? observedAt : Instant.now();
    }

    public Long getId() { return id; }
    public void setId(Long id) { this.id = id; }

    public Long getEntityId() { return entityId; }
    public void setEntityId(Long entityId) { this.entityId = entityId; }

    public String getCanonicalId() { return canonicalId; }
    public void setCanonicalId(String canonicalId) { this.canonicalId = canonicalId; }

    public String getSourceType() { return sourceType; }
    public void setSourceType(String sourceType) { this.sourceType = sourceType; }

    public String getSourceId() { return sourceId; }
    public void setSourceId(String sourceId) { this.sourceId = sourceId; }

    public String getHostContext() { return hostContext; }
    public void setHostContext(String hostContext) { this.hostContext = hostContext; }

    public String getRawEvidenceRef() { return rawEvidenceRef; }
    public void setRawEvidenceRef(String rawEvidenceRef) { this.rawEvidenceRef = rawEvidenceRef; }

    public String getObservedAttributesJson() { return observedAttributesJson; }
    public void setObservedAttributesJson(String observedAttributesJson) { this.observedAttributesJson = observedAttributesJson; }

    public double getConfidenceScore() { return confidenceScore; }
    public void setConfidenceScore(double confidenceScore) { this.confidenceScore = confidenceScore; }

    public Instant getObservedAt() { return observedAt; }
    public void setObservedAt(Instant observedAt) { this.observedAt = observedAt; }
}
