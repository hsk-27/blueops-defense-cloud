package com.blueops.response;

public enum ResponsePolicyOutcome {
    ALLOW,
    DENY,
    REQUIRE_APPROVAL,
    SIMULATION_ONLY,
    BLOCKED,
    INVALID
}
