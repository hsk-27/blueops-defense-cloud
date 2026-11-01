package com.blueops.incidents;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import java.util.List;

public class IncidentCreateRequest {

    @NotBlank(message = "Title is required")
    private String title;

    private String description;

    @NotNull(message = "Severity is required")
    private IncidentSeverity severity;

    private Long primaryAssetId;

    private List<String> findingIds;

    public IncidentCreateRequest() {}

    public String getTitle() { return title; }
    public void setTitle(String title) { this.title = title; }

    public String getDescription() { return description; }
    public void setDescription(String description) { this.description = description; }

    public IncidentSeverity getSeverity() { return severity; }
    public void setSeverity(IncidentSeverity severity) { this.severity = severity; }

    public Long getPrimaryAssetId() { return primaryAssetId; }
    public void setPrimaryAssetId(Long primaryAssetId) { this.primaryAssetId = primaryAssetId; }

    public List<String> getFindingIds() { return findingIds; }
    public void setFindingIds(List<String> findingIds) { this.findingIds = findingIds; }
}
