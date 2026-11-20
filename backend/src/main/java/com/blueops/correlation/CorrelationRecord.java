package com.blueops.correlation;

import com.blueops.entities.EntityType;
import com.blueops.incidents.IncidentSeverity;
import jakarta.persistence.*;
import java.time.Instant;

@Entity
@Table(name = "correlations")
public class CorrelationRecord {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "correlation_id", nullable = false, unique = true, length = 64)
    private String correlationId;

    @Column(name = "rule_id", nullable = false, length = 32)
    private String ruleId;

    @Column(name = "rule_name", nullable = false, length = 128)
    private String ruleName;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 32)
    private IncidentSeverity severity = IncidentSeverity.HIGH;

    @Column(name = "primary_entity_canonical_id", nullable = false, length = 255)
    private String primaryEntityCanonicalId;

    @Enumerated(EnumType.STRING)
    @Column(name = "primary_entity_type", nullable = false, length = 32)
    private EntityType primaryEntityType;

    @Column(nullable = false, columnDefinition = "TEXT")
    private String explanation;

    @Column(name = "first_finding_time", nullable = false)
    private Instant firstFindingTime;

    @Column(name = "last_finding_time", nullable = false)
    private Instant lastFindingTime;

    @Column(name = "incident_id")
    private Long incidentId;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 32)
    private CorrelationStatus status = CorrelationStatus.OPEN;

    @Column(name = "created_at", nullable = false, updatable = false)
    private Instant createdAt = Instant.now();

    @Column(name = "updated_at", nullable = false)
    private Instant updatedAt = Instant.now();

    public CorrelationRecord() {}

    public CorrelationRecord(String correlationId, String ruleId, String ruleName, IncidentSeverity severity,
                             String primaryEntityCanonicalId, EntityType primaryEntityType, String explanation,
                             Instant firstFindingTime, Instant lastFindingTime) {
        this.correlationId = correlationId;
        this.ruleId = ruleId;
        this.ruleName = ruleName;
        this.severity = severity;
        this.primaryEntityCanonicalId = primaryEntityCanonicalId;
        this.primaryEntityType = primaryEntityType;
        this.explanation = explanation;
        this.firstFindingTime = firstFindingTime;
        this.lastFindingTime = lastFindingTime;
        this.status = CorrelationStatus.OPEN;
        this.createdAt = Instant.now();
        this.updatedAt = Instant.now();
    }

    public Long getId() { return id; }
    public void setId(Long id) { this.id = id; }

    public String getCorrelationId() { return correlationId; }
    public void setCorrelationId(String correlationId) { this.correlationId = correlationId; }

    public String getRuleId() { return ruleId; }
    public void setRuleId(String ruleId) { this.ruleId = ruleId; }

    public String getRuleName() { return ruleName; }
    public void setRuleName(String ruleName) { this.ruleName = ruleName; }

    public IncidentSeverity getSeverity() { return severity; }
    public void setSeverity(IncidentSeverity severity) { this.severity = severity; }

    public String getPrimaryEntityCanonicalId() { return primaryEntityCanonicalId; }
    public void setPrimaryEntityCanonicalId(String primaryEntityCanonicalId) { this.primaryEntityCanonicalId = primaryEntityCanonicalId; }

    public EntityType getPrimaryEntityType() { return primaryEntityType; }
    public void setPrimaryEntityType(EntityType primaryEntityType) { this.primaryEntityType = primaryEntityType; }

    public String getExplanation() { return explanation; }
    public void setExplanation(String explanation) { this.explanation = explanation; }

    public Instant getFirstFindingTime() { return firstFindingTime; }
    public void setFirstFindingTime(Instant firstFindingTime) { this.firstFindingTime = firstFindingTime; }

    public Instant getLastFindingTime() { return lastFindingTime; }
    public void setLastFindingTime(Instant lastFindingTime) { this.lastFindingTime = lastFindingTime; }

    public Long getIncidentId() { return incidentId; }
    public void setIncidentId(Long incidentId) { this.incidentId = incidentId; }

    public CorrelationStatus getStatus() { return status; }
    public void setStatus(CorrelationStatus status) { this.status = status; }

    public Instant getCreatedAt() { return createdAt; }
    public void setCreatedAt(Instant createdAt) { this.createdAt = createdAt; }

    public Instant getUpdatedAt() { return updatedAt; }
    public void setUpdatedAt(Instant updatedAt) { this.updatedAt = updatedAt; }
}
