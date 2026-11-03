package com.blueops.auth;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class LoginRateLimiterTest {

    private LoginRateLimiter rateLimiter;

    @BeforeEach
    void setUp() {
        rateLimiter = new LoginRateLimiter();
    }

    @Test
    @DisplayName("Should allow initial attempts and block after 5 failed attempts")
    void shouldBlockAfterMaxFailures() {
        String testUser = "analyst.dev";

        assertFalse(rateLimiter.isBlocked(testUser));
        assertEquals(5, rateLimiter.getRemainingAttempts(testUser));

        // 4 failed attempts
        for (int i = 0; i < 4; i++) {
            rateLimiter.recordFailure(testUser);
            assertFalse(rateLimiter.isBlocked(testUser));
        }

        assertEquals(1, rateLimiter.getRemainingAttempts(testUser));

        // 5th failed attempt triggers lockout
        rateLimiter.recordFailure(testUser);
        assertTrue(rateLimiter.isBlocked(testUser));
        assertEquals(0, rateLimiter.getRemainingAttempts(testUser));
    }

    @Test
    @DisplayName("Should reset failures upon successful login")
    void shouldResetOnSuccess() {
        String testUser = "analyst.dev";

        rateLimiter.recordFailure(testUser);
        rateLimiter.recordFailure(testUser);
        assertEquals(3, rateLimiter.getRemainingAttempts(testUser));

        rateLimiter.recordSuccess(testUser);
        assertEquals(5, rateLimiter.getRemainingAttempts(testUser));
        assertFalse(rateLimiter.isBlocked(testUser));
    }
}
