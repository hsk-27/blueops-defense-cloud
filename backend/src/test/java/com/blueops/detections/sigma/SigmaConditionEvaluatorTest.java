package com.blueops.detections.sigma;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class SigmaConditionEvaluatorTest {

    private final SigmaConditionEvaluator evaluator = new SigmaConditionEvaluator();

    @Test
    @DisplayName("Should evaluate simple selection and binary boolean operations")
    void testBasicBooleanLogic() {
        Map<String, Boolean> outcomes = Map.of(
                "selection_image", true,
                "selection_flags", true,
                "selection_other", false
        );

        assertTrue(evaluator.evaluate("selection_image and selection_flags", outcomes));
        assertFalse(evaluator.evaluate("selection_image and selection_other", outcomes));
        assertTrue(evaluator.evaluate("selection_image or selection_other", outcomes));
        assertFalse(evaluator.evaluate("selection_other or not selection_image", outcomes));
    }

    @Test
    @DisplayName("Should evaluate NOT and parenthesized expressions")
    void testNotAndParentheses() {
        Map<String, Boolean> outcomes = Map.of(
                "selection", true,
                "filter_antivirus", true,
                "filter_standard", false
        );

        assertFalse(evaluator.evaluate("selection and not filter_antivirus", outcomes));
        assertTrue(evaluator.evaluate("selection and not filter_standard", outcomes));
        assertTrue(evaluator.evaluate("(selection and not filter_antivirus) or selection", outcomes));
    }

    @Test
    @DisplayName("Should evaluate quantifier wildcards: 1 of selection* and all of selection*")
    void testQuantifiers() {
        Map<String, Boolean> outcomes = Map.of(
                "selection_exec", false,
                "selection_file", true,
                "other_field", false
        );

        assertTrue(evaluator.evaluate("1 of selection*", outcomes));
        assertFalse(evaluator.evaluate("all of selection*", outcomes));
        assertTrue(evaluator.evaluate("1 of them", outcomes));
    }

    @Test
    @DisplayName("Should correctly strip aggregation expressions before evaluation")
    void testAggregationExpressionStripping() {
        Map<String, Boolean> outcomes = Map.of(
                "selection", true
        );

        // Standard aggregation rule condition
        String cond = "selection | count(event.id) by source.ip > 5";
        assertTrue(evaluator.evaluate(cond, outcomes));
    }
}
