package com.blueops.security;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.mock.env.MockEnvironment;

import static org.junit.jupiter.api.Assertions.*;

class SecurityStartupValidatorTest {

    @Test
    @DisplayName("Should pass startup validation with valid lab development keys in non-prod environment")
    void testValidLabKeysPassInDev() {
        MockEnvironment env = new MockEnvironment();
        env.setActiveProfiles("dev", "test");

        SecurityStartupValidator validator = new SecurityStartupValidator(
                "c3948e9a2b71450a89274e0d9b4317f2a8934c71829045b61928374650192837",
                "b7c938d10b7f43a99e1d8847e923832c3f59194e432c7e436814041b65b16130",
                env
        );

        assertDoesNotThrow(validator::validateSecurityPostures);
    }

    @Test
    @DisplayName("Should fail startup validation if secret has insufficient entropy (< 256 bits) in production")
    void testInsufficientEntropyFailsInProd() {
        MockEnvironment env = new MockEnvironment();
        env.setActiveProfiles("prod");

        SecurityStartupValidator validator = new SecurityStartupValidator(
                "short-secret-key-too-short",
                "b7c938d10b7f43a99e1d8847e923832c3f59194e432c7e436814041b65b16130",
                env
        );

        assertThrows(IllegalStateException.class, validator::validateSecurityPostures);
    }

    @Test
    @DisplayName("Should fail startup validation if default lab secret is used in production profile")
    void testDefaultSecretFailsInProd() {
        MockEnvironment env = new MockEnvironment();
        env.setActiveProfiles("prod");

        SecurityStartupValidator validator = new SecurityStartupValidator(
                "c3948e9a2b71450a89274e0d9b4317f2a8934c71829045b61928374650192837",
                "b7c938d10b7f43a99e1d8847e923832c3f59194e432c7e436814041b65b16130",
                env
        );

        assertThrows(IllegalStateException.class, validator::validateSecurityPostures);
    }

    @Test
    @DisplayName("Should pass startup validation in production if strong custom secrets are injected")
    void testStrongCustomSecretsPassInProd() {
        MockEnvironment env = new MockEnvironment();
        env.setActiveProfiles("prod");

        SecurityStartupValidator validator = new SecurityStartupValidator(
                "my-ultra-secure-production-jwt-token-signing-key-9988224411",
                "my-ultra-secure-production-hmac-agent-signing-key-8877665522",
                env
        );

        assertDoesNotThrow(validator::validateSecurityPostures);
    }
}
