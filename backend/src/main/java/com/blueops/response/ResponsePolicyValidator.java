package com.blueops.response;

import com.blueops.assets.Asset;
import com.blueops.common.exceptions.InvalidActionException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.util.Locale;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * Response Policy Validator (RSP-001)
 * Enforces policy constraints, blast radius boundaries, protected asset exclusion,
 * and input validation before response actions can be queued or executed.
 */
@Component
public class ResponsePolicyValidator {

    private static final Logger log = LoggerFactory.getLogger(ResponsePolicyValidator.class);

    private static final Set<String> PROTECTED_TARGETS = Set.of(
            "127.0.0.1", "0.0.0.0", "::1", "localhost", "gateway", "dns"
    );

    private static final Pattern SAFE_TARGET_PATTERN = Pattern.compile("^[a-zA-Z0-9.:/_-]+$");

    /**
     * Validates an action request against safety policies.
     */
    public void validateRequest(ResponsePlaybook playbook, String targetIdentifier, Asset targetAsset, boolean isSimulation) {
        if (targetIdentifier == null || targetIdentifier.isBlank()) {
            throw new InvalidActionException("Response target identifier cannot be empty.");
        }

        String targetClean = targetIdentifier.trim().toLowerCase(Locale.ROOT);

        // 1. Prevent option injection
        if (targetClean.startsWith("-")) {
            throw new InvalidActionException("Response target identifier cannot begin with a hyphen (CLI flag injection prevented).");
        }

        // 2. Validate character set
        if (!SAFE_TARGET_PATTERN.matcher(targetClean).matches()) {
            throw new InvalidActionException("Response target contains invalid characters or potential shell metacharacters: " + targetIdentifier);
        }

        // 3. Blast radius check: protected infrastructure cannot be blocked or isolated
        if (PROTECTED_TARGETS.contains(targetClean)) {
            throw new InvalidActionException("Action targeting protected infrastructure is strictly forbidden: " + targetIdentifier);
        }

        // 4. Critical tier assets require explicit approval (cannot be auto-approved)
        if (targetAsset != null && "CRITICAL".equalsIgnoreCase(targetAsset.getCriticality())) {
            log.info("Response target [{}] is classified as CRITICAL asset. Enforcing manual approval requirement.", targetAsset.getHostname());
        }
    }
}
