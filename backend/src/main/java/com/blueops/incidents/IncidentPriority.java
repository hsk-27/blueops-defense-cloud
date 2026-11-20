package com.blueops.incidents;

/**
 * Operational handling urgency for an Incident (M4).
 * Distinct from IncidentSeverity (which represents assessed technical impact).
 */
public enum IncidentPriority {
    P1_CRITICAL,
    P2_HIGH,
    P3_MEDIUM,
    P4_LOW;

    public static IncidentPriority fromSeverity(IncidentSeverity severity) {
        if (severity == null) return P3_MEDIUM;
        return switch (severity) {
            case CRITICAL -> P1_CRITICAL;
            case HIGH -> P2_HIGH;
            case MEDIUM -> P3_MEDIUM;
            case LOW -> P4_LOW;
        };
    }
}
