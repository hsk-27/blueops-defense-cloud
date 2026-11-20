package com.blueops.security;

import jakarta.annotation.PostConstruct;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.env.Environment;
import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;
import java.util.*;

/**
 * Security Startup Validator (SEC-001)
 * Enforces cryptographic Shannon entropy constraints, blocks predictable keys,
 * and ensures default development secrets cannot be deployed insecurely into production environments.
 */
@Component
public class SecurityStartupValidator {

    private static final Logger log = LoggerFactory.getLogger(SecurityStartupValidator.class);

    private static final Set<String> PRODUCTION_PROFILE_ALIASES = Set.of(
            "prod", "production", "prd", "live"
    );

    private static final List<String> KNOWN_INSECURE_SECRETS = List.of(
            "b7c938d10b7f43a99e1d8847e923832c3f59194e432c7e436814041b65b16130",
            "c3948e9a2b71450a89274e0d9b4317f2a8934c71829045b61928374650192837",
            "secret",
            "changeme",
            "default_secret",
            "password"
    );

    // Minimum required Shannon entropy (bits per character) for cryptographic keys
    private static final double MIN_SHANNON_ENTROPY = 3.0;
    // Minimum required unique characters in the key
    private static final int MIN_UNIQUE_CHARS = 8;
    // Minimum required key length (bytes) for HMAC-SHA256
    private static final int MIN_KEY_BYTES = 32;

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
        boolean isProduction = isProductionEnvironment();

        // 1. Validate JWT Secret
        validateSecret("JWT Secret Key", jwtSecret, isProduction);

        // 2. Validate Response Agent HMAC Secret
        validateSecret("Response Agent HMAC Secret", responseAgentSecret, isProduction);

        // 3. Log posture summary
        byte[] jwtBytes = jwtSecret != null ? jwtSecret.getBytes(StandardCharsets.UTF_8) : new byte[0];
        byte[] agentBytes = responseAgentSecret != null ? responseAgentSecret.getBytes(StandardCharsets.UTF_8) : new byte[0];
        log.info("Cryptographic startup validation verified: JWT ({} bits, H={}), HMAC-SHA256 ({} bits, H={}), Profiles: {}",
                jwtBytes.length * 8, String.format(Locale.ROOT, "%.2f", calculateShannonEntropy(jwtSecret)),
                agentBytes.length * 8, String.format(Locale.ROOT, "%.2f", calculateShannonEntropy(responseAgentSecret)),
                Arrays.toString(environment.getActiveProfiles()));
    }

    private void validateSecret(String secretName, String secret, boolean isProduction) {
        if (secret == null || secret.isBlank()) {
            String errorMsg = "CRITICAL SECURITY FAULT: " + secretName + " is null or empty.";
            log.error(errorMsg);
            if (isProduction) throw new IllegalStateException(errorMsg);
            return;
        }

        byte[] secretBytes = secret.getBytes(StandardCharsets.UTF_8);
        double entropy = calculateShannonEntropy(secret);
        int uniqueChars = countUniqueCharacters(secret);
        boolean isPredictable = isPredictablePattern(secret);

        // Check byte length bound (at least 256 bits / 32 bytes)
        if (secretBytes.length < MIN_KEY_BYTES) {
            String errorMsg = String.format(Locale.ROOT,
                    "CRITICAL SECURITY FAULT: %s has insufficient byte length (< %d bytes / 256 bits). Found: %d bytes (%d bits).",
                    secretName, MIN_KEY_BYTES, secretBytes.length, secretBytes.length * 8);
            log.error(errorMsg);
            if (isProduction) throw new IllegalStateException(errorMsg);
        }

        // Check genuine Shannon Information Entropy
        if (entropy < MIN_SHANNON_ENTROPY || uniqueChars < MIN_UNIQUE_CHARS || isPredictable) {
            String errorMsg = String.format(Locale.ROOT,
                    "CRITICAL SECURITY FAULT: %s has insufficient cryptographic entropy or predictable pattern (H=%.2f < %.1f, uniqueChars=%d, predictable=%b).",
                    secretName, entropy, MIN_SHANNON_ENTROPY, uniqueChars, isPredictable);
            log.error(errorMsg);
            if (isProduction) throw new IllegalStateException(errorMsg);
        }

        // Check known blacklisted default development keys
        if (isProduction && isBlacklistedSecret(secret)) {
            String errorMsg = "FATAL SECURITY CONFIGURATION: Known default development secret detected for " + secretName + " in active production profile. Deployment aborted.";
            log.error(errorMsg);
            throw new IllegalStateException(errorMsg);
        } else if (!isProduction && isBlacklistedSecret(secret)) {
            log.warn("================================================================================");
            log.warn("  SECURITY NOTICE: {} is running with a pre-configured development/lab key.", secretName);
            log.warn("  For production deployments, inject BLUEOPS_JWT_SECRET and RESPONSE_AGENT_SECRET.");
            log.warn("================================================================================");
        }
    }

    /**
     * Determines if any active profile matches production aliases.
     */
    public boolean isProductionEnvironment() {
        if (environment == null || environment.getActiveProfiles() == null) {
            return false;
        }
        for (String profile : environment.getActiveProfiles()) {
            if (profile != null && PRODUCTION_PROFILE_ALIASES.contains(profile.trim().toLowerCase(Locale.ROOT))) {
                return true;
            }
        }
        return false;
    }

    /**
     * Calculates Shannon Information Entropy H(X) in bits per character.
     * H(X) = -sum(P(x) * log2(P(x)))
     */
    public static double calculateShannonEntropy(String input) {
        if (input == null || input.isEmpty()) return 0.0;
        Map<Character, Integer> freqMap = new HashMap<>();
        for (char c : input.toCharArray()) {
            freqMap.put(c, freqMap.getOrDefault(c, 0) + 1);
        }
        double entropy = 0.0;
        int len = input.length();
        for (int count : freqMap.values()) {
            double p = (double) count / len;
            entropy -= p * (Math.log(p) / Math.log(2.0));
        }
        return entropy;
    }

    public static int countUniqueCharacters(String input) {
        if (input == null || input.isEmpty()) return 0;
        Set<Character> unique = new HashSet<>();
        for (char c : input.toCharArray()) {
            unique.add(c);
        }
        return unique.size();
    }

    public static boolean isPredictablePattern(String input) {
        if (input == null || input.length() < 4) return true;
        // Check for repeated identical characters (e.g. "aaaaaaaaaaaaaaaa")
        if (countUniqueCharacters(input) <= 2) return true;
        // Check for simple repeated halves (e.g. "passwordpassword")
        int len = input.length();
        if (len % 2 == 0) {
            String firstHalf = input.substring(0, len / 2);
            String secondHalf = input.substring(len / 2);
            if (firstHalf.equals(secondHalf)) return true;
        }
        // Check for repeated 4-character chunks (e.g. "1234123412341234")
        if (len >= 8 && len % 4 == 0) {
            String chunk = input.substring(0, 4);
            boolean allMatch = true;
            for (int i = 4; i <= len - 4; i += 4) {
                if (!input.substring(i, i + 4).equals(chunk)) {
                    allMatch = false;
                    break;
                }
            }
            if (allMatch) return true;
        }
        return false;
    }

    private static boolean isBlacklistedSecret(String secret) {
        if (secret == null) return false;
        String normalized = secret.trim().toLowerCase(Locale.ROOT);
        for (String blacklisted : KNOWN_INSECURE_SECRETS) {
            if (normalized.equals(blacklisted.toLowerCase(Locale.ROOT))) {
                return true;
            }
        }
        return false;
    }
}
