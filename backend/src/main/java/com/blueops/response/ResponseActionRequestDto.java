package com.blueops.response;

import jakarta.validation.constraints.NotBlank;

public class ResponseActionRequestDto {

    @NotBlank(message = "Playbook code is required")
    private String playbookCode; // P001, P002, P003

    private Long incidentId;

    @NotBlank(message = "Target identifier (IP, user, or asset) is required")
    private String targetIdentifier;

    private Long targetAssetId;

    private boolean simulation = true;

    public ResponseActionRequestDto() {}

    public String getPlaybookCode() { return playbookCode; }
    public void setPlaybookCode(String playbookCode) { this.playbookCode = playbookCode; }

    public Long getIncidentId() { return incidentId; }
    public void setIncidentId(Long incidentId) { this.incidentId = incidentId; }

    public String getTargetIdentifier() { return targetIdentifier; }
    public void setTargetIdentifier(String targetIdentifier) { this.targetIdentifier = targetIdentifier; }

    public Long getTargetAssetId() { return targetAssetId; }
    public void setTargetAssetId(Long targetAssetId) { this.targetAssetId = targetAssetId; }

    public boolean isSimulation() { return simulation; }
    public void setSimulation(boolean simulation) { this.simulation = simulation; }
}
