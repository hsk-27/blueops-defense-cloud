package com.blueops.entities;

import jakarta.persistence.*;
import java.time.Instant;

@Entity
@Table(name = "entity_relationships", uniqueConstraints = {
    @UniqueConstraint(name = "uq_entity_relationship", columnNames = {"source_canonical_id", "target_canonical_id", "relation_type"})
})
public class EntityRelationshipRecord {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "source_canonical_id", nullable = false, length = 255)
    private String sourceCanonicalId;

    @Column(name = "target_canonical_id", nullable = false, length = 255)
    private String targetCanonicalId;

    @Enumerated(EnumType.STRING)
    @Column(name = "relation_type", nullable = false, length = 64)
    private EntityRelationType relationType;

    @Column(name = "confidence_score", nullable = false)
    private double confidenceScore = 1.0;

    @Column(name = "observation_count", nullable = false)
    private long observationCount = 1;

    @Column(name = "evidence_description", length = 512)
    private String evidenceDescription;

    @Column(name = "provenance_source", length = 64)
    private String provenanceSource;

    @Column(name = "first_observed", nullable = false)
    private Instant firstObserved = Instant.now();

    @Column(name = "last_observed", nullable = false)
    private Instant lastObserved = Instant.now();

    @Column(name = "created_at", nullable = false, updatable = false)
    private Instant createdAt = Instant.now();

    @Column(name = "updated_at", nullable = false)
    private Instant updatedAt = Instant.now();

    public EntityRelationshipRecord() {}

    public EntityRelationshipRecord(String sourceCanonicalId, String targetCanonicalId,
                                    EntityRelationType relationType, double confidenceScore,
                                    String evidenceDescription, String provenanceSource) {
        this.sourceCanonicalId = sourceCanonicalId;
        this.targetCanonicalId = targetCanonicalId;
        this.relationType = relationType;
        this.confidenceScore = confidenceScore;
        this.evidenceDescription = evidenceDescription;
        this.provenanceSource = provenanceSource;
        this.firstObserved = Instant.now();
        this.lastObserved = Instant.now();
        this.createdAt = Instant.now();
        this.updatedAt = Instant.now();
    }

    public Long getId() { return id; }
    public void setId(Long id) { this.id = id; }

    public String getSourceCanonicalId() { return sourceCanonicalId; }
    public void setSourceCanonicalId(String sourceCanonicalId) { this.sourceCanonicalId = sourceCanonicalId; }

    public String getTargetCanonicalId() { return targetCanonicalId; }
    public void setTargetCanonicalId(String targetCanonicalId) { this.targetCanonicalId = targetCanonicalId; }

    public EntityRelationType getRelationType() { return relationType; }
    public void setRelationType(EntityRelationType relationType) { this.relationType = relationType; }

    public double getConfidenceScore() { return confidenceScore; }
    public void setConfidenceScore(double confidenceScore) { this.confidenceScore = confidenceScore; }

    public long getObservationCount() { return observationCount; }
    public void setObservationCount(long observationCount) { this.observationCount = observationCount; }

    public String getEvidenceDescription() { return evidenceDescription; }
    public void setEvidenceDescription(String evidenceDescription) { this.evidenceDescription = evidenceDescription; }

    public String getProvenanceSource() { return provenanceSource; }
    public void setProvenanceSource(String provenanceSource) { this.provenanceSource = provenanceSource; }

    public Instant getFirstObserved() { return firstObserved; }
    public void setFirstObserved(Instant firstObserved) { this.firstObserved = firstObserved; }

    public Instant getLastObserved() { return lastObserved; }
    public void setLastObserved(Instant lastObserved) { this.lastObserved = lastObserved; }

    public Instant getCreatedAt() { return createdAt; }
    public void setCreatedAt(Instant createdAt) { this.createdAt = createdAt; }

    public Instant getUpdatedAt() { return updatedAt; }
    public void setUpdatedAt(Instant updatedAt) { this.updatedAt = updatedAt; }
}
