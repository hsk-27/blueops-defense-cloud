package com.blueops.security;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.mock.env.MockEnvironment;

import static org.junit.jupiter.api.Assertions.*;

class SecurityStartupValidatorTest {

    private static final String STRONG_JWT_SECRET = "b7c938d10b7f43a99e1d8847e923832c3f59194e432c7e436814041b65b16130";
    private static final String STRONG_PROD_JWT = "aB3$kL9#mP2&vX7*qW4!zR8(yT1^uI6@oF5%";
    private static final String STRONG_PROD_HMAC = "kL9#mP2&vX7*qW4!zR8(yT1^uI6@oF5%aB3$";

    @Test
    @DisplayName("Should pass startup validation with valid lab development keys in non-prod environment")
    void testValidLabKeysPassInDev() {
        MockEnvironment env = new MockEnvironment();
        env.setActiveProfiles("dev", "test");

        SecurityStartupValidator validator = new SecurityStartupValidator(
                "c3948e9a2b71450a89274e0d9b4317f2a8934c71829045b61928374650192837",
                STRONG_JWT_SECRET,
                env
        );

        assertDoesNotThrow(validator::validateSecurityPostures);
    }

    @ParameterizedTest
    @ValueSource(strings = {"prod", "production", "prd", "live"})
    @DisplayName("Should recognize all production profile aliases and reject default lab secrets")
    void testDefaultSecretFailsInAllProductionAliases(String profile) {
        MockEnvironment env = new MockEnvironment();
        env.setActiveProfiles(profile);

        SecurityStartupValidator validator = new SecurityStartupValidator(
                "c3948e9a2b71450a89274e0d9b4317f2a8934c71829045b61928374650192837",
                STRONG_JWT_SECRET,
                env
        );

        assertThrows(IllegalStateException.class, validator::validateSecurityPostures);
    }

    @Test
    @DisplayName("Should fail startup validation if secret length is less than 32 bytes in production")
    void testInsufficientByteLengthFailsInProd() {
        MockEnvironment env = new MockEnvironment();
        env.setActiveProfiles("production");

        SecurityStartupValidator validator = new SecurityStartupValidator(
                "short-secret-key-too-short",
                STRONG_PROD_HMAC,
                env
        );

        assertThrows(IllegalStateException.class, validator::validateSecurityPostures);
    }

    @Test
    @DisplayName("Should fail startup validation if secret has 32 bytes but zero Shannon entropy (repetitive characters)")
    void testRepetitiveSecretFailsDueToLowEntropyInProd() {
        MockEnvironment env = new MockEnvironment();
        env.setActiveProfiles("prod");

        // 32 identical characters: byte length is 32, but Shannon entropy is 0.0
        String zeroEntropySecret = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        assertEquals(32, zeroEntropySecret.length());
        assertEquals(0.0, SecurityStartupValidator.calculateShannonEntropy(zeroEntropySecret));

        SecurityStartupValidator validator = new SecurityStartupValidator(
                zeroEntropySecret,
                STRONG_PROD_HMAC,
                env
        );

        assertThrows(IllegalStateException.class, validator::validateSecurityPostures);
    }

    @Test
    @DisplayName("Should fail startup validation for predictable repeated sequence (e.g. repeated 4-character chunks)")
    void testRepeatedSequenceFailsInProd() {
        MockEnvironment env = new MockEnvironment();
        env.setActiveProfiles("production");

        // 32 chars made of repeated "1234" chunk
        String predictableSecret = "12341234123412341234123412341234";
        assertTrue(SecurityStartupValidator.isPredictablePattern(predictableSecret));

        SecurityStartupValidator validator = new SecurityStartupValidator(
                predictableSecret,
                STRONG_PROD_HMAC,
                env
        );

        assertThrows(IllegalStateException.class, validator::validateSecurityPostures);
    }

    @Test
    @DisplayName("Should pass startup validation in production if high-entropy secrets are injected")
    void testStrongCustomSecretsPassInProd() {
        MockEnvironment env = new MockEnvironment();
        env.setActiveProfiles("production");

        assertTrue(SecurityStartupValidator.calculateShannonEntropy(STRONG_PROD_JWT) >= 3.8);
        assertTrue(SecurityStartupValidator.calculateShannonEntropy(STRONG_PROD_HMAC) >= 3.8);

        SecurityStartupValidator validator = new SecurityStartupValidator(
                STRONG_PROD_JWT,
                STRONG_PROD_HMAC,
                env
        );

        assertDoesNotThrow(validator::validateSecurityPostures);
    }
}
