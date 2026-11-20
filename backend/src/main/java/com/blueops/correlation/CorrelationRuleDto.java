package com.blueops.correlation;

import com.blueops.incidents.IncidentSeverity;
import java.time.Instant;

public class CorrelationRuleDto {
    private Long id;
    private String ruleId;
    private String name;
    private String description;
    private IncidentSeverity severity;
    private String groupingField;
    private int timeWindowMinutes;
    private String conditionsJson;
    private boolean enabled;
    private Instant createdAt;

    public CorrelationRuleDto() {}

    public CorrelationRuleDto(Long id, String ruleId, String name, String description, IncidentSeverity severity,
                              String groupingField, int timeWindowMinutes, String conditionsJson, boolean enabled, Instant createdAt) {
        this.id = id;
        this.ruleId = ruleId;
        this.name = name;
        this.description = description;
        this.severity = severity;
        this.groupingField = groupingField;
        this.timeWindowMinutes = timeWindowMinutes;
        this.conditionsJson = conditionsJson;
        this.enabled = enabled;
        this.createdAt = createdAt;
    }

    public Long getId() { return id; }
    public void setId(Long id) { this.id = id; }

    public String getRuleId() { return ruleId; }
    public void setRuleId(String ruleId) { this.ruleId = ruleId; }

    public String getName() { return name; }
    public void setName(String name) { this.name = name; }

    public String getDescription() { return description; }
    public void setDescription(String description) { this.description = description; }

    public IncidentSeverity getSeverity() { return severity; }
    public void setSeverity(IncidentSeverity severity) { this.severity = severity; }

    public String getGroupingField() { return groupingField; }
    public void setGroupingField(String groupingField) { this.groupingField = groupingField; }

    public int getTimeWindowMinutes() { return timeWindowMinutes; }
    public void setTimeWindowMinutes(int timeWindowMinutes) { this.timeWindowMinutes = timeWindowMinutes; }

    public String getConditionsJson() { return conditionsJson; }
    public void setConditionsJson(String conditionsJson) { this.conditionsJson = conditionsJson; }

    public boolean isEnabled() { return enabled; }
    public void setEnabled(boolean enabled) { this.enabled = enabled; }

    public Instant getCreatedAt() { return createdAt; }
    public void setCreatedAt(Instant createdAt) { this.createdAt = createdAt; }
}
