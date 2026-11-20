package com.blueops.incidents;

import java.util.Set;

public enum IncidentStatus {
    NEW,
    TRIAGED,
    INVESTIGATING,
    CONTAINMENT_PENDING,
    CONTAINED,
    RESOLVED,
    CLOSED,
    FALSE_POSITIVE,
    REOPENED;

    public boolean canTransitionTo(IncidentStatus next) {
        if (this == next) return true;

        switch (this) {
            case NEW:
                return Set.of(TRIAGED, INVESTIGATING, FALSE_POSITIVE).contains(next);
            case TRIAGED:
                return Set.of(INVESTIGATING, FALSE_POSITIVE, RESOLVED).contains(next);
            case INVESTIGATING:
                return Set.of(CONTAINMENT_PENDING, CONTAINED, RESOLVED, FALSE_POSITIVE).contains(next);
            case CONTAINMENT_PENDING:
                return Set.of(CONTAINED, INVESTIGATING, RESOLVED).contains(next);
            case CONTAINED:
                return Set.of(RESOLVED, INVESTIGATING).contains(next);
            case RESOLVED:
                return Set.of(CLOSED, REOPENED).contains(next);
            case FALSE_POSITIVE:
                return Set.of(CLOSED, REOPENED).contains(next);
            case CLOSED:
                return next == REOPENED;
            case REOPENED:
                return Set.of(TRIAGED, INVESTIGATING).contains(next);
            default:
                return false;
        }
    }
}
