package com.blueops.correlation;

import jakarta.persistence.*;

@Entity
@Table(name = "correlation_findings", uniqueConstraints = {
    @UniqueConstraint(name = "uq_corr_finding", columnNames = {"correlation_id", "finding_id"})
})
public class CorrelationFindingRecord {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "correlation_id", nullable = false)
    private Long correlationId;

    @Column(name = "finding_id", nullable = false, length = 64)
    private String findingId;

    public CorrelationFindingRecord() {}

    public CorrelationFindingRecord(Long correlationId, String findingId) {
        this.correlationId = correlationId;
        this.findingId = findingId;
    }

    public Long getId() { return id; }
    public void setId(Long id) { this.id = id; }

    public Long getCorrelationId() { return correlationId; }
    public void setCorrelationId(Long correlationId) { this.correlationId = correlationId; }

    public String getFindingId() { return findingId; }
    public void setFindingId(String findingId) { this.findingId = findingId; }
}
