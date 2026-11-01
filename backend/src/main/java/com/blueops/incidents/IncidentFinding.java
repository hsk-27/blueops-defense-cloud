package com.blueops.incidents;

import jakarta.persistence.*;
import java.time.Instant;

@Entity
@Table(name = "incident_findings")
public class IncidentFinding {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "incident_id", nullable = false)
    private Incident incident;

    @Column(name = "opensearch_finding_id", nullable = false, length = 128)
    private String opensearchFindingId;

    @Column(name = "rule_code", nullable = false, length = 32)
    private String ruleCode;

    @Column(name = "rule_name", nullable = false, length = 128)
    private String ruleName;

    @Column(nullable = false, length = 32)
    private String severity;

    @Column(name = "detected_at", nullable = false)
    private Instant detectedAt;

    @Column(name = "raw_document_id", length = 128)
    private String rawDocumentId;

    @Column(name = "details_json", columnDefinition = "TEXT")
    private String detailsJson;

    public IncidentFinding() {}

    public IncidentFinding(Incident incident, String opensearchFindingId, String ruleCode, String ruleName, String severity, Instant detectedAt, String rawDocumentId, String detailsJson) {
        this.incident = incident;
        this.opensearchFindingId = opensearchFindingId;
        this.ruleCode = ruleCode;
        this.ruleName = ruleName;
        this.severity = severity;
        this.detectedAt = detectedAt;
        this.rawDocumentId = rawDocumentId;
        this.detailsJson = detailsJson;
    }

    public Long getId() { return id; }
    public void setId(Long id) { this.id = id; }

    public Incident getIncident() { return incident; }
    public void setIncident(Incident incident) { this.incident = incident; }

    public String getOpensearchFindingId() { return opensearchFindingId; }
    public void setOpensearchFindingId(String opensearchFindingId) { this.opensearchFindingId = opensearchFindingId; }

    public String getRuleCode() { return ruleCode; }
    public void setRuleCode(String ruleCode) { this.ruleCode = ruleCode; }

    public String getRuleName() { return ruleName; }
    public void setRuleName(String ruleName) { this.ruleName = ruleName; }

    public String getSeverity() { return severity; }
    public void setSeverity(String severity) { this.severity = severity; }

    public Instant getDetectedAt() { return detectedAt; }
    public void setDetectedAt(Instant detectedAt) { this.detectedAt = detectedAt; }

    public String getRawDocumentId() { return rawDocumentId; }
    public void setRawDocumentId(String rawDocumentId) { this.rawDocumentId = rawDocumentId; }

    public String getDetailsJson() { return detailsJson; }
    public void setDetailsJson(String detailsJson) { this.detailsJson = detailsJson; }
}
