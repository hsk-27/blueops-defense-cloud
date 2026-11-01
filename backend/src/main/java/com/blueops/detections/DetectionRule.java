package com.blueops.detections;

import jakarta.persistence.*;
import java.time.Instant;

@Entity
@Table(name = "detection_rules")
public class DetectionRule {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "rule_code", nullable = false, unique = true, length = 32)
    private String ruleCode;

    @Column(nullable = false, length = 128)
    private String name;

    @Column(nullable = false, columnDefinition = "TEXT")
    private String description;

    @Column(name = "log_source", nullable = false, length = 64)
    private String logSource;

    @Column(nullable = false, length = 32)
    private String severity;

    @Column(name = "mitre_tactic", nullable = false, length = 64)
    private String mitreTactic;

    @Column(name = "mitre_technique_id", nullable = false, length = 32)
    private String mitreTechniqueId;

    @Column(name = "mitre_technique_name", nullable = false, length = 128)
    private String mitreTechniqueName;

    @Column(nullable = false, length = 32)
    private String status = "ACTIVE"; // ACTIVE, DISABLED, TESTING

    @Column(name = "query_dsl", nullable = false, columnDefinition = "TEXT")
    private String queryDsl;

    @Column(name = "sigma_yaml", columnDefinition = "TEXT")
    private String sigmaYaml;

    @Column(name = "false_positives", columnDefinition = "TEXT")
    private String falsePositives;

    @Column(nullable = false)
    private int version = 1;

    @Column(name = "created_at", nullable = false, updatable = false)
    private Instant createdAt = Instant.now();

    @Column(name = "updated_at", nullable = false)
    private Instant updatedAt = Instant.now();

    public DetectionRule() {}

    public Long getId() { return id; }
    public void setId(Long id) { this.id = id; }

    public String getRuleCode() { return ruleCode; }
    public void setRuleCode(String ruleCode) { this.ruleCode = ruleCode; }

    public String getName() { return name; }
    public void setName(String name) { this.name = name; }

    public String getDescription() { return description; }
    public void setDescription(String description) { this.description = description; }

    public String getLogSource() { return logSource; }
    public void setLogSource(String logSource) { this.logSource = logSource; }

    public String getSeverity() { return severity; }
    public void setSeverity(String severity) { this.severity = severity; }

    public String getMitreTactic() { return mitreTactic; }
    public void setMitreTactic(String mitreTactic) { this.mitreTactic = mitreTactic; }

    public String getMitreTechniqueId() { return mitreTechniqueId; }
    public void setMitreTechniqueId(String mitreTechniqueId) { this.mitreTechniqueId = mitreTechniqueId; }

    public String getMitreTechniqueName() { return mitreTechniqueName; }
    public void setMitreTechniqueName(String mitreTechniqueName) { this.mitreTechniqueName = mitreTechniqueName; }

    public String getStatus() { return status; }
    public void setStatus(String status) { this.status = status; }

    public String getQueryDsl() { return queryDsl; }
    public void setQueryDsl(String queryDsl) { this.queryDsl = queryDsl; }

    public String getSigmaYaml() { return sigmaYaml; }
    public void setSigmaYaml(String sigmaYaml) { this.sigmaYaml = sigmaYaml; }

    public String getFalsePositives() { return falsePositives; }
    public void setFalsePositives(String falsePositives) { this.falsePositives = falsePositives; }

    public int getVersion() { return version; }
    public void setVersion(int version) { this.version = version; }

    public Instant getCreatedAt() { return createdAt; }
    public void setCreatedAt(Instant createdAt) { this.createdAt = createdAt; }

    public Instant getUpdatedAt() { return updatedAt; }
    public void setUpdatedAt(Instant updatedAt) { this.updatedAt = updatedAt; }
}
