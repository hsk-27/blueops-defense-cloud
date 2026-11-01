package com.blueops.response;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.time.Instant;

import static org.junit.jupiter.api.Assertions.*;

class HmacSignatureServiceTest {

    private HmacSignatureService hmacSignatureService;

    @BeforeEach
    void setUp() {
        hmacSignatureService = new HmacSignatureService("test-secret-key-12345");
    }

    @Test
    void testSignAndVerify() {
        String payload = "{\"action\":\"BLOCK_IP\",\"target\":\"198.51.100.24\"}";
        long timestamp = Instant.now().getEpochSecond();

        String sig = hmacSignatureService.signPayload(payload, timestamp);
        assertNotNull(sig);
        assertTrue(hmacSignatureService.verifySignature(payload, timestamp, sig));
    }

    @Test
    void testTamperedPayloadFails() {
        String payload = "{\"action\":\"BLOCK_IP\",\"target\":\"198.51.100.24\"}";
        long timestamp = Instant.now().getEpochSecond();

        String sig = hmacSignatureService.signPayload(payload, timestamp);
        assertFalse(hmacSignatureService.verifySignature("{\"action\":\"BLOCK_IP\",\"target\":\"198.51.100.25\"}", timestamp, sig));
    }
}
