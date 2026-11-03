package com.blueops.advisory;

public enum AdvisoryPriority {
    IMMEDIATE_ACTION(1, "Critical, immediate action required to halt ongoing adversary compromise."),
    HIGH_PRIORITY(2, "High-urgency procedural step required to stabilize investigation or isolate asset."),
    RECOMMENDED_FOLLOW_UP(3, "Recommended forensic or analytical follow-up action."),
    STRATEGIC_HARDENING(4, "Post-remediation configuration hardening to prevent recurring compromise.");

    private final int rank;
    private final String description;

    AdvisoryPriority(int rank, String description) {
        this.rank = rank;
        this.description = description;
    }

    public int getRank() {
        return rank;
    }

    public String getDescription() {
        return description;
    }
}
