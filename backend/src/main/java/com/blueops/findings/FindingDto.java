package com.blueops.findings;

import java.time.Instant;
import java.util.Map;

public class FindingDto {
    private String findingId;
    private String detectorId;
    private String detectorName;
    private String ruleId;
    private String ruleName;
    private String ruleSeverity;
    private String mitreTactic;
    private String mitreTechniqueId;
    private String mitreTechniqueName;
    private String assetId;
    private String assetName;
    private Instant timestamp;
    private String status; // UNASSIGNED, LINKED_TO_INCIDENT, RESOLVED
    private String relatedDocId;
    private Map<String, Object> details;

    public FindingDto() {}

    public FindingDto(String findingId, String ruleId, String ruleName, String ruleSeverity, String mitreTactic,
                      String mitreTechniqueId, String mitreTechniqueName, String assetId, String assetName,
                      Instant timestamp, String status, String relatedDocId, Map<String, Object> details) {
        this.findingId = findingId;
        this.ruleId = ruleId;
        this.ruleName = ruleName;
        this.ruleSeverity = ruleSeverity;
        this.mitreTactic = mitreTactic;
        this.mitreTechniqueId = mitreTechniqueId;
        this.mitreTechniqueName = mitreTechniqueName;
        this.assetId = assetId;
        this.assetName = assetName;
        this.timestamp = timestamp;
        this.status = status;
        this.relatedDocId = relatedDocId;
        this.details = details;
    }

    public String getFindingId() { return findingId; }
    public void setFindingId(String findingId) { this.findingId = findingId; }

    public String getDetectorId() { return detectorId; }
    public void setDetectorId(String detectorId) { this.detectorId = detectorId; }

    public String getDetectorName() { return detectorName; }
    public void setDetectorName(String detectorName) { this.detectorName = detectorName; }

    public String getRuleId() { return ruleId; }
    public void setRuleId(String ruleId) { this.ruleId = ruleId; }

    public String getRuleName() { return ruleName; }
    public void setRuleName(String ruleName) { this.ruleName = ruleName; }

    public String getRuleSeverity() { return ruleSeverity; }
    public void setRuleSeverity(String ruleSeverity) { this.ruleSeverity = ruleSeverity; }

    public String getMitreTactic() { return mitreTactic; }
    public void setMitreTactic(String mitreTactic) { this.mitreTactic = mitreTactic; }

    public String getMitreTechniqueId() { return mitreTechniqueId; }
    public void setMitreTechniqueId(String mitreTechniqueId) { this.mitreTechniqueId = mitreTechniqueId; }

    public String getMitreTechniqueName() { return mitreTechniqueName; }
    public void setMitreTechniqueName(String mitreTechniqueName) { this.mitreTechniqueName = mitreTechniqueName; }

    public String getAssetId() { return assetId; }
    public void setAssetId(String assetId) { this.assetId = assetId; }

    public String getAssetName() { return assetName; }
    public void setAssetName(String assetName) { this.assetName = assetName; }

    public Instant getTimestamp() { return timestamp; }
    public void setTimestamp(Instant timestamp) { this.timestamp = timestamp; }

    public String getStatus() { return status; }
    public void setStatus(String status) { this.status = status; }

    public String getRelatedDocId() { return relatedDocId; }
    public void setRelatedDocId(String relatedDocId) { this.relatedDocId = relatedDocId; }

    public Map<String, Object> getDetails() { return details; }
    public void setDetails(Map<String, Object> details) { this.details = details; }
}
