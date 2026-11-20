package com.blueops.findings;

/**
 * Related Finding Association Model (M4 - Section 7).
 * Connects findings via defensible association criteria (shared asset, shared entity,
 * shared tactic, temporal proximity) without requiring complex graph engines.
 */
public class RelatedFindingDto {
    private FindingDto finding;
    private String relationType; // SHARED_ASSET, SHARED_SOURCE_IP, SHARED_TACTIC, TEMPORAL_RULE_PROXIMITY
    private String relationshipRationale;
    private double confidenceScore;

    public RelatedFindingDto() {}

    public RelatedFindingDto(FindingDto finding, String relationType, String relationshipRationale, double confidenceScore) {
        this.finding = finding;
        this.relationType = relationType;
        this.relationshipRationale = relationshipRationale;
        this.confidenceScore = confidenceScore;
    }

    public FindingDto getFinding() { return finding; }
    public void setFinding(FindingDto finding) { this.finding = finding; }

    public String getRelationType() { return relationType; }
    public void setRelationType(String relationType) { this.relationType = relationType; }

    public String getRelationshipRationale() { return relationshipRationale; }
    public void setRelationshipRationale(String relationshipRationale) { this.relationshipRationale = relationshipRationale; }

    public double getConfidenceScore() { return confidenceScore; }
    public void setConfidenceScore(double confidenceScore) { this.confidenceScore = confidenceScore; }
}
