package com.blueops.auth;

import org.springframework.stereotype.Component;

import java.time.Instant;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

@Component
public class LoginRateLimiter {

    private static final int MAX_FAILED_ATTEMPTS = 5;
    private static final long LOCKOUT_DURATION_SECONDS = 900; // 15 minutes

    private static class AttemptRecord {
        int failedAttempts;
        Instant lockoutUntil;

        AttemptRecord(int count, Instant lockoutUntil) {
            this.failedAttempts = count;
            this.lockoutUntil = lockoutUntil;
        }
    }

    private final Map<String, AttemptRecord> attempts = new ConcurrentHashMap<>();

    public boolean isBlocked(String key) {
        if (key == null) return false;
        AttemptRecord record = attempts.get(key);
        if (record == null) return false;

        if (record.lockoutUntil != null) {
            if (Instant.now().isBefore(record.lockoutUntil)) {
                return true;
            } else {
                // Lockout period expired
                attempts.remove(key);
                return false;
            }
        }
        return false;
    }

    public void recordFailure(String key) {
        if (key == null) return;
        attempts.compute(key, (k, record) -> {
            Instant now = Instant.now();
            if (record == null || (record.lockoutUntil != null && now.isAfter(record.lockoutUntil))) {
                return new AttemptRecord(1, null);
            }
            int newCount = record.failedAttempts + 1;
            Instant lockout = null;
            if (newCount >= MAX_FAILED_ATTEMPTS) {
                lockout = now.plusSeconds(LOCKOUT_DURATION_SECONDS);
            }
            return new AttemptRecord(newCount, lockout);
        });
    }

    public void recordSuccess(String key) {
        if (key != null) {
            attempts.remove(key);
        }
    }

    public int getRemainingAttempts(String key) {
        if (key == null) return MAX_FAILED_ATTEMPTS;
        AttemptRecord record = attempts.get(key);
        if (record == null) return MAX_FAILED_ATTEMPTS;
        return Math.max(0, MAX_FAILED_ATTEMPTS - record.failedAttempts);
    }

    public void reset() {
        attempts.clear();
    }
}
