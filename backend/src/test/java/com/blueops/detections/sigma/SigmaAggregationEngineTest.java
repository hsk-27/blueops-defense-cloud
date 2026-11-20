package com.blueops.detections.sigma;

import com.blueops.findings.FindingDto;
import com.blueops.telemetry.NormalizedEvent;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class SigmaAggregationEngineTest {

    private SigmaAggregationEngine aggregationEngine;
    private SigmaConditionEvaluator conditionEvaluator;

    @BeforeEach
    void setUp() {
        aggregationEngine = new SigmaAggregationEngine();
        conditionEvaluator = new SigmaConditionEvaluator();
    }

    private SigmaRuleDefinition createD001Rule() {
        SigmaRuleDefinition rule = new SigmaRuleDefinition();
        rule.setId("d001-test");
        rule.setRuleCode("D001");
        rule.setTitle("Repeated SSH Authentication Failures");
        rule.setDetection(Map.of(
                "selection", Map.of("action", "failed_login"),
                "condition", "selection | count(event.id) by source.ip > 5",
                "timeframe", "5m"
        ));
        return rule;
    }

    private SigmaRuleDefinition createD002Rule() {
        SigmaRuleDefinition rule = new SigmaRuleDefinition();
        rule.setId("d002-test");
        rule.setRuleCode("D002");
        rule.setTitle("Successful SSH Login After Failures");
        rule.setDetection(Map.of(
                "selection_fail", Map.of("action", "failed_login"),
                "selection_success", Map.of("action", "successful_login"),
                "condition", "selection_fail and selection_success by source.ip",
                "timeframe", "10m"
        ));
        return rule;
    }

    private NormalizedEvent createAuthEvent(String srcIp, String action, Instant time) {
        NormalizedEvent event = new NormalizedEvent();
        event.setId("evt-" + System.nanoTime());
        event.setTimestamp(time);
        event.setHost(new NormalizedEvent.HostMetadata("LNX-01", "LNX-SRV-01", srcIp, "Linux", "6.5"));
        event.setSource(new NormalizedEvent.NetworkEndpoint(srcIp, 2222, null));
        event.setDestination(new NormalizedEvent.NetworkEndpoint("192.168.1.10", 22, null));
        event.setEvent(new NormalizedEvent.EventMetadata(
                event.getId(), "Linux-auditd", "linux.auth",
                List.of("authentication"), List.of("logon"), action, 3, null
        ));
        return event;
    }

    @Test
    @DisplayName("Should NOT trigger D001 on single or isolated authentication failures (< threshold)")
    void testD001DoesNotTriggerPrematurely() {
        SigmaRuleDefinition rule = createD001Rule();
        Instant now = Instant.now();
        NormalizedEvent event = createAuthEvent("198.51.100.44", "failed_login", now);
        Map<String, Boolean> outcomes = Map.of("selection", true);

        // 1st failure: count = 1 <= 5 -> should NOT trigger
        boolean matched1 = aggregationEngine.evaluateAggregation(rule, event, outcomes, conditionEvaluator);
        assertFalse(matched1, "Single failure must not trigger D001 (eliminates false positives)");

        // 5th failure: count = 5 <= 5 -> should NOT trigger (> 5 threshold)
        for (int i = 2; i <= 5; i++) {
            boolean matched = aggregationEngine.evaluateAggregation(rule, event, outcomes, conditionEvaluator);
            assertFalse(matched, "Failure " + i + " must not trigger D001");
        }
    }

    @Test
    @DisplayName("Should trigger D001 when count threshold (> 5) is exceeded within the 5-minute sliding window")
    void testD001TriggersWhenThresholdExceeded() {
        SigmaRuleDefinition rule = createD001Rule();
        Instant now = Instant.now();
        NormalizedEvent event = createAuthEvent("198.51.100.44", "failed_login", now);
        Map<String, Boolean> outcomes = Map.of("selection", true);

        // Send 5 failures
        for (int i = 1; i <= 5; i++) {
            assertFalse(aggregationEngine.evaluateAggregation(rule, event, outcomes, conditionEvaluator));
        }

        // 6th failure exceeds threshold (> 5) -> triggers
        boolean matched6 = aggregationEngine.evaluateAggregation(rule, event, outcomes, conditionEvaluator);
        assertTrue(matched6, "6th failure must trigger D001");
    }

    @Test
    @DisplayName("Should prune failures outside sliding window so spaced-out failures do not accumulate indefinitely")
    void testSlidingWindowPrunesExpiredEvents() {
        SigmaRuleDefinition rule = createD001Rule(); // 5m window
        Instant now = Instant.now();
        Map<String, Boolean> outcomes = Map.of("selection", true);

        // 4 failures 10 minutes ago (expired)
        Instant oldTime = now.minusSeconds(600);
        NormalizedEvent oldEvent = createAuthEvent("198.51.100.44", "failed_login", oldTime);
        for (int i = 0; i < 4; i++) {
            aggregationEngine.evaluateAggregation(rule, oldEvent, outcomes, conditionEvaluator);
        }

        // 2 failures now (total live in window = 2 <= 5)
        NormalizedEvent currentEvent = createAuthEvent("198.51.100.44", "failed_login", now);
        assertFalse(aggregationEngine.evaluateAggregation(rule, currentEvent, outcomes, conditionEvaluator));
        assertFalse(aggregationEngine.evaluateAggregation(rule, currentEvent, outcomes, conditionEvaluator));
    }

    @Test
    @DisplayName("Should evaluate D002 sequence: Failure followed by Success on the same source IP within timeframe")
    void testD002SequenceCorrelation() {
        SigmaRuleDefinition rule = createD002Rule();
        Instant now = Instant.now();

        // 1. Failure event arrives
        NormalizedEvent failEvent = createAuthEvent("198.51.100.99", "failed_login", now);
        Map<String, Boolean> failOutcomes = Map.of("selection_fail", true, "selection_success", false);
        boolean failMatched = aggregationEngine.evaluateAggregation(rule, failEvent, failOutcomes, conditionEvaluator);
        assertFalse(failMatched, "Failure alone must not trigger D002");

        // 2. Success event arrives 30 seconds later from same IP
        NormalizedEvent successEvent = createAuthEvent("198.51.100.99", "successful_login", now.plusSeconds(30));
        Map<String, Boolean> successOutcomes = Map.of("selection_fail", false, "selection_success", true);
        boolean successMatched = aggregationEngine.evaluateAggregation(rule, successEvent, successOutcomes, conditionEvaluator);
        assertTrue(successMatched, "Success following failure must trigger D002 sequence");

        // 3. Second success without subsequent failure should not trigger again
        boolean secondSuccess = aggregationEngine.evaluateAggregation(rule, successEvent, successOutcomes, conditionEvaluator);
        assertFalse(secondSuccess, "Duplicate success should not trigger without another failure");
    }
}
