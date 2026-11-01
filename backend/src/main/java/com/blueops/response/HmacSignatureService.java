package com.blueops.response;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.HexFormat;

@Service
public class HmacSignatureService {

    private static final Logger log = LoggerFactory.getLogger(HmacSignatureService.class);
    private final String secretKey;

    public HmacSignatureService(@Value("${blueops.response-agent.secret:b7c938d10b7f43a99e1d8847e923832c3f59194e432c7e436814041b65b16130}") String secretKey) {
        this.secretKey = secretKey;
    }

    public String signPayload(String payload, long timestamp) {
        try {
            String message = timestamp + ":" + payload;
            Mac sha256Hmac = Mac.getInstance("HmacSHA256");
            SecretKeySpec secretKeySpec = new SecretKeySpec(secretKey.getBytes(StandardCharsets.UTF_8), "HmacSHA256");
            sha256Hmac.init(secretKeySpec);
            byte[] hash = sha256Hmac.doFinal(message.getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(hash);
        } catch (Exception ex) {
            log.error("Failed to generate HMAC-SHA256 signature: {}", ex.getMessage());
            throw new RuntimeException("HMAC signing failure", ex);
        }
    }

    public boolean verifySignature(String payload, long timestamp, String signature) {
        try {
            String expected = signPayload(payload, timestamp);
            return MessageDigest.isEqual(expected.getBytes(StandardCharsets.UTF_8), signature.getBytes(StandardCharsets.UTF_8));
        } catch (Exception ex) {
            return false;
        }
    }
}
