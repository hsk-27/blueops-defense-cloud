package com.blueops.correlation;

import com.blueops.incidents.IncidentSeverity;
import jakarta.persistence.*;
import java.time.Instant;

@Entity
@Table(name = "correlation_rules")
public class CorrelationRuleRecord {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "rule_id", nullable = false, unique = true, length = 32)
    private String ruleId;

    @Column(nullable = false, length = 128)
    private String name;

    @Column(nullable = false, columnDefinition = "TEXT")
    private String description;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 32)
    private IncidentSeverity severity = IncidentSeverity.HIGH;

    @Column(name = "grouping_field", nullable = false, length = 32)
    private String groupingField = "ENTITY_HOST";

    @Column(name = "time_window_minutes", nullable = false)
    private int timeWindowMinutes = 60;

    @Column(name = "conditions_json", nullable = false, columnDefinition = "TEXT")
    private String conditionsJson;

    @Column(nullable = false)
    private boolean enabled = true;

    @Column(name = "created_at", nullable = false, updatable = false)
    private Instant createdAt = Instant.now();

    @Column(name = "updated_at", nullable = false)
    private Instant updatedAt = Instant.now();

    public CorrelationRuleRecord() {}

    public CorrelationRuleRecord(String ruleId, String name, String description, IncidentSeverity severity,
                                 String groupingField, int timeWindowMinutes, String conditionsJson, boolean enabled) {
        this.ruleId = ruleId;
        this.name = name;
        this.description = description;
        this.severity = severity;
        this.groupingField = groupingField;
        this.timeWindowMinutes = timeWindowMinutes;
        this.conditionsJson = conditionsJson;
        this.enabled = enabled;
        this.createdAt = Instant.now();
        this.updatedAt = Instant.now();
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

    public Instant getUpdatedAt() { return updatedAt; }
    public void setUpdatedAt(Instant updatedAt) { this.updatedAt = updatedAt; }
}
