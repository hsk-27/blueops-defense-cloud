package com.blueops.entities;

import java.time.Instant;
import java.util.Map;

public class EntityObservationDto {
    private Long id;
    private Long entityId;
    private String canonicalId;
    private String sourceType;
    private String sourceId;
    private String hostContext;
    private String rawEvidenceRef;
    private Map<String, Object> observedAttributes;
    private double confidenceScore;
    private Instant observedAt;

    public EntityObservationDto() {}

    public EntityObservationDto(Long id, Long entityId, String canonicalId, String sourceType, String sourceId,
                                String hostContext, String rawEvidenceRef, Map<String, Object> observedAttributes,
                                double confidenceScore, Instant observedAt) {
        this.id = id;
        this.entityId = entityId;
        this.canonicalId = canonicalId;
        this.sourceType = sourceType;
        this.sourceId = sourceId;
        this.hostContext = hostContext;
        this.rawEvidenceRef = rawEvidenceRef;
        this.observedAttributes = observedAttributes;
        this.confidenceScore = confidenceScore;
        this.observedAt = observedAt;
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

    public Map<String, Object> getObservedAttributes() { return observedAttributes; }
    public void setObservedAttributes(Map<String, Object> observedAttributes) { this.observedAttributes = observedAttributes; }

    public double getConfidenceScore() { return confidenceScore; }
    public void setConfidenceScore(double confidenceScore) { this.confidenceScore = confidenceScore; }

    public Instant getObservedAt() { return observedAt; }
    public void setObservedAt(Instant observedAt) { this.observedAt = observedAt; }
}
