package com.blueops.advisory;

public enum AdvisoryPhase {
    DETECTION_AND_ANALYSIS("Detection & Analysis", "Scoping, evidence gathering, IOC validation, and impact assessment."),
    CONTAINMENT("Containment", "Immediate isolation, session revocation, and lateral movement limitation."),
    ERADICATION("Eradication", "Malware removal, persistence eviction, and root cause mitigation."),
    RECOVERY("Recovery", "Safe restoration of system operations, golden image rebuild, and validation."),
    POST_INCIDENT("Post-Incident Activity", "Lessons learned, rule tuning, threat hunting sweeps, and metric review.");

    private final String displayName;
    private final String description;

    AdvisoryPhase(String displayName, String description) {
        this.displayName = displayName;
        this.description = description;
    }

    public String getDisplayName() {
        return displayName;
    }

    public String getDescription() {
        return description;
    }
}
