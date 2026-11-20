package com.blueops.entities;

import java.time.Instant;

public class EntityRelationshipDto {
    private Long id;
    private String sourceCanonicalId;
    private String targetCanonicalId;
    private EntityRelationType relationType;
    private double confidenceScore;
    private long observationCount;
    private String evidenceDescription;
    private String provenanceSource;
    private Instant firstObserved;
    private Instant lastObserved;

    public EntityRelationshipDto() {}

    public EntityRelationshipDto(Long id, String sourceCanonicalId, String targetCanonicalId,
                                 EntityRelationType relationType, double confidenceScore,
                                 long observationCount, String evidenceDescription,
                                 String provenanceSource, Instant firstObserved, Instant lastObserved) {
        this.id = id;
        this.sourceCanonicalId = sourceCanonicalId;
        this.targetCanonicalId = targetCanonicalId;
        this.relationType = relationType;
        this.confidenceScore = confidenceScore;
        this.observationCount = observationCount;
        this.evidenceDescription = evidenceDescription;
        this.provenanceSource = provenanceSource;
        this.firstObserved = firstObserved;
        this.lastObserved = lastObserved;
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
}
