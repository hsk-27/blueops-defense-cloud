package com.blueops.detections;

import java.time.Instant;

public class DetectionRuleDto {
    private Long id;
    private String ruleCode;
    private String name;
    private String description;
    private String logSource;
    private String severity;
    private String mitreTactic;
    private String mitreTechniqueId;
    private String mitreTechniqueName;
    private String status;
    private String queryDsl;
    private String sigmaYaml;
    private String falsePositives;
    private int version;
    private Instant createdAt;
    private Instant updatedAt;

    public DetectionRuleDto() {}

    public DetectionRuleDto(DetectionRule rule) {
        this.id = rule.getId();
        this.ruleCode = rule.getRuleCode();
        this.name = rule.getName();
        this.description = rule.getDescription();
        this.logSource = rule.getLogSource();
        this.severity = rule.getSeverity();
        this.mitreTactic = rule.getMitreTactic();
        this.mitreTechniqueId = rule.getMitreTechniqueId();
        this.mitreTechniqueName = rule.getMitreTechniqueName();
        this.status = rule.getStatus();
        this.queryDsl = rule.getQueryDsl();
        this.sigmaYaml = rule.getSigmaYaml();
        this.falsePositives = rule.getFalsePositives();
        this.version = rule.getVersion();
        this.createdAt = rule.getCreatedAt();
        this.updatedAt = rule.getUpdatedAt();
    }

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
