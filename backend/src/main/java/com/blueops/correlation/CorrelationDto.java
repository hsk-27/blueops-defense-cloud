package com.blueops.correlation;

import com.blueops.entities.EntityType;
import com.blueops.incidents.IncidentSeverity;

import java.time.Instant;
import java.util.List;

public class CorrelationDto {
    private Long id;
    private String correlationId;
    private String ruleId;
    private String ruleName;
    private IncidentSeverity severity;
    private String primaryEntityCanonicalId;
    private EntityType primaryEntityType;
    private String explanation;
    private Instant firstFindingTime;
    private Instant lastFindingTime;
    private Long incidentId;
    private CorrelationStatus status;
    private List<String> correlatedFindingIds;
    private List<String> correlatedEntityIds;
    private Instant createdAt;

    public CorrelationDto() {}

    public CorrelationDto(Long id, String correlationId, String ruleId, String ruleName, IncidentSeverity severity,
                          String primaryEntityCanonicalId, EntityType primaryEntityType, String explanation,
                          Instant firstFindingTime, Instant lastFindingTime, Long incidentId, CorrelationStatus status,
                          List<String> correlatedFindingIds, List<String> correlatedEntityIds, Instant createdAt) {
        this.id = id;
        this.correlationId = correlationId;
        this.ruleId = ruleId;
        this.ruleName = ruleName;
        this.severity = severity;
        this.primaryEntityCanonicalId = primaryEntityCanonicalId;
        this.primaryEntityType = primaryEntityType;
        this.explanation = explanation;
        this.firstFindingTime = firstFindingTime;
        this.lastFindingTime = lastFindingTime;
        this.incidentId = incidentId;
        this.status = status;
        this.correlatedFindingIds = correlatedFindingIds;
        this.correlatedEntityIds = correlatedEntityIds;
        this.createdAt = createdAt;
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

    public List<String> getCorrelatedFindingIds() { return correlatedFindingIds; }
    public void setCorrelatedFindingIds(List<String> correlatedFindingIds) { this.correlatedFindingIds = correlatedFindingIds; }

    public List<String> getCorrelatedEntityIds() { return correlatedEntityIds; }
    public void setCorrelatedEntityIds(List<String> correlatedEntityIds) { this.correlatedEntityIds = correlatedEntityIds; }

    public Instant getCreatedAt() { return createdAt; }
    public void setCreatedAt(Instant createdAt) { this.createdAt = createdAt; }
}
