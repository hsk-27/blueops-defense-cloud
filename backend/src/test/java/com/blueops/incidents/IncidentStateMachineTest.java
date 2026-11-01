package com.blueops.incidents;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class IncidentStateMachineTest {

    @Test
    void testValidTransitions() {
        assertTrue(IncidentStatus.NEW.canTransitionTo(IncidentStatus.TRIAGED));
        assertTrue(IncidentStatus.TRIAGED.canTransitionTo(IncidentStatus.INVESTIGATING));
        assertTrue(IncidentStatus.INVESTIGATING.canTransitionTo(IncidentStatus.CONTAINMENT_PENDING));
        assertTrue(IncidentStatus.CONTAINMENT_PENDING.canTransitionTo(IncidentStatus.CONTAINED));
        assertTrue(IncidentStatus.CONTAINED.canTransitionTo(IncidentStatus.RESOLVED));
        assertTrue(IncidentStatus.RESOLVED.canTransitionTo(IncidentStatus.REOPENED));
        assertTrue(IncidentStatus.NEW.canTransitionTo(IncidentStatus.FALSE_POSITIVE));
    }

    @Test
    void testInvalidTransitions() {
        assertFalse(IncidentStatus.NEW.canTransitionTo(IncidentStatus.RESOLVED));
        assertFalse(IncidentStatus.NEW.canTransitionTo(IncidentStatus.CONTAINED));
        assertFalse(IncidentStatus.CONTAINED.canTransitionTo(IncidentStatus.TRIAGED));
        assertFalse(IncidentStatus.RESOLVED.canTransitionTo(IncidentStatus.INVESTIGATING));
    }
}
