package com.blueops.incidents;

import java.time.Instant;

public class IncidentDto {
    private Long id;
    private String incidentNumber;
    private String title;
    private String description;
    private String severity;
    private String status;
    private Long primaryAssetId;
    private String primaryAssetHostname;
    private String primaryAssetIp;
    private String assignedTo;
    private String createdBy;
    private String resolutionRationale;
    private Instant createdAt;
    private Instant updatedAt;
    private Instant containedAt;
    private Instant resolvedAt;
    private int findingCount;
    private int noteCount;

    public IncidentDto() {}

    public IncidentDto(Incident incident) {
        this.id = incident.getId();
        this.incidentNumber = incident.getIncidentNumber();
        this.title = incident.getTitle();
        this.description = incident.getDescription();
        this.severity = incident.getSeverity().name();
        this.status = incident.getStatus().name();
        if (incident.getPrimaryAsset() != null) {
            this.primaryAssetId = incident.getPrimaryAsset().getId();
            this.primaryAssetHostname = incident.getPrimaryAsset().getHostname();
            this.primaryAssetIp = incident.getPrimaryAsset().getIpAddress();
        }
        this.assignedTo = incident.getAssignedTo();
        this.createdBy = incident.getCreatedBy();
        this.resolutionRationale = incident.getResolutionRationale();
        this.createdAt = incident.getCreatedAt();
        this.updatedAt = incident.getUpdatedAt();
        this.containedAt = incident.getContainedAt();
        this.resolvedAt = incident.getResolvedAt();
        this.findingCount = incident.getFindings() != null ? incident.getFindings().size() : 0;
        this.noteCount = incident.getNotes() != null ? incident.getNotes().size() : 0;
    }

    public Long getId() { return id; }
    public void setId(Long id) { this.id = id; }

    public String getIncidentNumber() { return incidentNumber; }
    public void setIncidentNumber(String incidentNumber) { this.incidentNumber = incidentNumber; }

    public String getTitle() { return title; }
    public void setTitle(String title) { this.title = title; }

    public String getDescription() { return description; }
    public void setDescription(String description) { this.description = description; }

    public String getSeverity() { return severity; }
    public void setSeverity(String severity) { this.severity = severity; }

    public String getStatus() { return status; }
    public void setStatus(String status) { this.status = status; }

    public Long getPrimaryAssetId() { return primaryAssetId; }
    public void setPrimaryAssetId(Long primaryAssetId) { this.primaryAssetId = primaryAssetId; }

    public String getPrimaryAssetHostname() { return primaryAssetHostname; }
    public void setPrimaryAssetHostname(String primaryAssetHostname) { this.primaryAssetHostname = primaryAssetHostname; }

    public String getPrimaryAssetIp() { return primaryAssetIp; }
    public void setPrimaryAssetIp(String primaryAssetIp) { this.primaryAssetIp = primaryAssetIp; }

    public String getAssignedTo() { return assignedTo; }
    public void setAssignedTo(String assignedTo) { this.assignedTo = assignedTo; }

    public String getCreatedBy() { return createdBy; }
    public void setCreatedBy(String createdBy) { this.createdBy = createdBy; }

    public String getResolutionRationale() { return resolutionRationale; }
    public void setResolutionRationale(String resolutionRationale) { this.resolutionRationale = resolutionRationale; }

    public Instant getCreatedAt() { return createdAt; }
    public void setCreatedAt(Instant createdAt) { this.createdAt = createdAt; }

    public Instant getUpdatedAt() { return updatedAt; }
    public void setUpdatedAt(Instant updatedAt) { this.updatedAt = updatedAt; }

    public Instant getContainedAt() { return containedAt; }
    public void setContainedAt(Instant containedAt) { this.containedAt = containedAt; }

    public Instant getResolvedAt() { return resolvedAt; }
    public void setResolvedAt(Instant resolvedAt) { this.resolvedAt = resolvedAt; }

    public int getFindingCount() { return findingCount; }
    public void setFindingCount(int findingCount) { this.findingCount = findingCount; }

    public int getNoteCount() { return noteCount; }
    public void setNoteCount(int noteCount) { this.noteCount = noteCount; }
}
