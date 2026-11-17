package com.blueops.security;

import jakarta.annotation.PostConstruct;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.env.Environment;
import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.List;

/**
 * Security Startup Validator (REM-001)
 * Enforces cryptographic entropy constraints and ensures default development
 * secrets cannot be deployed insecurely into production environments.
 */
@Component
public class SecurityStartupValidator {

    private static final Logger log = LoggerFactory.getLogger(SecurityStartupValidator.class);

    private static final List<String> KNOWN_INSECURE_SECRETS = List.of(
            "b7c938d10b7f43a99e1d8847e923832c3f59194e432c7e436814041b65b16130",
            "c3948e9a2b71450a89274e0d9b4317f2a8934c71829045b61928374650192837",
            "secret",
            "changeme",
            "default_secret"
    );

    private final String jwtSecret;
    private final String responseAgentSecret;
    private final Environment environment;

    public SecurityStartupValidator(
            @Value("${blueops.jwt.secret:c3948e9a2b71450a89274e0d9b4317f2a8934c71829045b61928374650192837}") String jwtSecret,
            @Value("${blueops.response-agent.secret:b7c938d10b7f43a99e1d8847e923832c3f59194e432c7e436814041b65b16130}") String responseAgentSecret,
            Environment environment) {
        this.jwtSecret = jwtSecret;
        this.responseAgentSecret = responseAgentSecret;
        this.environment = environment;
    }

    @PostConstruct
    public void validateSecurityPostures() {
        boolean isProduction = Arrays.asList(environment.getActiveProfiles()).contains("prod");

        // 1. Validate JWT Secret Entropy (At least 256 bits / 32 bytes)
        byte[] jwtBytes = jwtSecret.getBytes(StandardCharsets.UTF_8);
        if (jwtBytes.length < 32) {
            String errorMsg = "CRITICAL SECURITY FAULT: JWT Secret key has insufficient entropy (< 256 bits). Length: " + (jwtBytes.length * 8) + " bits.";
            log.error(errorMsg);
            if (isProduction) {
                throw new IllegalStateException(errorMsg);
            }
        }

        // 2. Validate Response Agent HMAC Secret Entropy
        byte[] agentBytes = responseAgentSecret.getBytes(StandardCharsets.UTF_8);
        if (agentBytes.length < 32) {
            String errorMsg = "CRITICAL SECURITY FAULT: Response Agent HMAC Secret key has insufficient entropy (< 256 bits).";
            log.error(errorMsg);
            if (isProduction) {
                throw new IllegalStateException(errorMsg);
            }
        }

        // 3. Check for Default / Placeholder Secrets in Production
        if (isProduction) {
            if (KNOWN_INSECURE_SECRETS.contains(jwtSecret) || KNOWN_INSECURE_SECRETS.contains(responseAgentSecret)) {
                String errorMsg = "FATAL SECURITY CONFIGURATION: Known default development secrets detected in active 'prod' profile. Deployment aborted.";
                log.error(errorMsg);
                throw new IllegalStateException(errorMsg);
            }
        } else {
            if (KNOWN_INSECURE_SECRETS.contains(jwtSecret) || KNOWN_INSECURE_SECRETS.contains(responseAgentSecret)) {
                log.warn("================================================================================");
                log.warn("  SECURITY NOTICE: Running with pre-configured development/lab cryptographic keys.");
                log.warn("  For production deployments, inject BLUEOPS_JWT_SECRET and RESPONSE_AGENT_SECRET.");
                log.warn("================================================================================");
            }
        }

        log.info("Cryptographic startup validation verified: JWT ({} bits), HMAC-SHA256 ({} bits), Profile: {}",
                jwtBytes.length * 8, agentBytes.length * 8, Arrays.toString(environment.getActiveProfiles()));
    }
}
