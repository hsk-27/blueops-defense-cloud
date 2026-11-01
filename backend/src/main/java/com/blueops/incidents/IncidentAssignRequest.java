package com.blueops.incidents;

import jakarta.validation.constraints.NotBlank;

public class IncidentAssignRequest {

    @NotBlank(message = "Assigned user is required")
    private String assignedTo;

    public IncidentAssignRequest() {}

    public IncidentAssignRequest(String assignedTo) {
        this.assignedTo = assignedTo;
    }

    public String getAssignedTo() { return assignedTo; }
    public void setAssignedTo(String assignedTo) { this.assignedTo = assignedTo; }
}
