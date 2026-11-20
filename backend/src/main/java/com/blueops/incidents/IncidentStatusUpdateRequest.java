package com.blueops.incidents;

import jakarta.validation.constraints.NotNull;

public class IncidentStatusUpdateRequest {

    @NotNull(message = "New status is required")
    private IncidentStatus status;

    private String reason;
    private String resolutionRationale;
    private String closureNotes;

    public IncidentStatusUpdateRequest() {}

    public IncidentStatus getStatus() { return status; }
    public void setStatus(IncidentStatus status) { this.status = status; }

    public String getReason() { return reason; }
    public void setReason(String reason) { this.reason = reason; }

    public String getResolutionRationale() { return resolutionRationale; }
    public void setResolutionRationale(String resolutionRationale) { this.resolutionRationale = resolutionRationale; }

    public String getClosureNotes() { return closureNotes; }
    public void setClosureNotes(String closureNotes) { this.closureNotes = closureNotes; }
}
