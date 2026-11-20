package com.blueops.correlation;

import jakarta.persistence.*;

@Entity
@Table(name = "correlation_entities", uniqueConstraints = {
    @UniqueConstraint(name = "uq_corr_entity", columnNames = {"correlation_id", "entity_canonical_id"})
})
public class CorrelationEntityRecord {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "correlation_id", nullable = false)
    private Long correlationId;

    @Column(name = "entity_canonical_id", nullable = false, length = 255)
    private String entityCanonicalId;

    public CorrelationEntityRecord() {}

    public CorrelationEntityRecord(Long correlationId, String entityCanonicalId) {
        this.correlationId = correlationId;
        this.entityCanonicalId = entityCanonicalId;
    }

    public Long getId() { return id; }
    public void setId(Long id) { this.id = id; }

    public Long getCorrelationId() { return correlationId; }
    public void setCorrelationId(Long correlationId) { this.correlationId = correlationId; }

    public String getEntityCanonicalId() { return entityCanonicalId; }
    public void setEntityCanonicalId(String entityCanonicalId) { this.entityCanonicalId = entityCanonicalId; }
}
