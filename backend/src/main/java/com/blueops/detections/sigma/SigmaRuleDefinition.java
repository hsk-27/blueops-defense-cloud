package com.blueops.detections.sigma;

import java.util.List;
import java.util.Map;

/**
 * Parsed representation of a declarative Sigma detection rule YAML specification.
 */
public class SigmaRuleDefinition {

    private String ruleCode;
    private String title;
    private String id;
    private String status;
    private String description;
    private String level;
    private String author;
    private String date;
    private String mitreTechniqueId;
    private String mitreTactic;
    private List<String> tags;
    private List<String> references;
    private List<String> falsePositives;
    private Map<String, Object> logsource;
    private Map<String, Object> detection;
    private String sourceFilePath;

    public SigmaRuleDefinition() {}

    public String getRuleCode() {
        return ruleCode;
    }

    public void setRuleCode(String ruleCode) {
        this.ruleCode = ruleCode;
    }

    public String getTitle() {
        return title;
    }

    public void setTitle(String title) {
        this.title = title;
    }

    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }

    public String getStatus() {
        return status;
    }

    public void setStatus(String status) {
        this.status = status;
    }

    public String getDescription() {
        return description;
    }

    public void setDescription(String description) {
        this.description = description;
    }

    public String getLevel() {
        return level;
    }

    public void setLevel(String level) {
        this.level = level;
    }

    public String getAuthor() {
        return author;
    }

    public void setAuthor(String author) {
        this.author = author;
    }

    public String getDate() {
        return date;
    }

    public void setDate(String date) {
        this.date = date;
    }

    public String getMitreTechniqueId() {
        return mitreTechniqueId;
    }

    public void setMitreTechniqueId(String mitreTechniqueId) {
        this.mitreTechniqueId = mitreTechniqueId;
    }

    public String getMitreTactic() {
        return mitreTactic;
    }

    public void setMitreTactic(String mitreTactic) {
        this.mitreTactic = mitreTactic;
    }

    public List<String> getTags() {
        return tags;
    }

    public void setTags(List<String> tags) {
        this.tags = tags;
    }

    public List<String> getReferences() {
        return references;
    }

    public void setReferences(List<String> references) {
        this.references = references;
    }

    public List<String> getFalsePositives() {
        return falsePositives;
    }

    public void setFalsePositives(List<String> falsePositives) {
        this.falsePositives = falsePositives;
    }

    public Map<String, Object> getLogsource() {
        return logsource;
    }

    public void setLogsource(Map<String, Object> logsource) {
        this.logsource = logsource;
    }

    public Map<String, Object> getDetection() {
        return detection;
    }

    public void setDetection(Map<String, Object> detection) {
        this.detection = detection;
    }

    public String getSourceFilePath() {
        return sourceFilePath;
    }

    public void setSourceFilePath(String sourceFilePath) {
        this.sourceFilePath = sourceFilePath;
    }
}
