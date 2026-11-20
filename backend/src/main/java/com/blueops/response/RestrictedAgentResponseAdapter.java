package com.blueops.response;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.web.client.RestTemplateBuilder;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestTemplate;

import java.time.Duration;
import java.time.Instant;

@Component
public class RestrictedAgentResponseAdapter implements ResponseAdapter {

    private static final Logger log = LoggerFactory.getLogger(RestrictedAgentResponseAdapter.class);

    private final HmacSignatureService hmacSignatureService;
    private final RestTemplate restTemplate;

    @Value("${blueops.response-agent.url:http://localhost:5000}")
    private String responseAgentUrl;

    public RestrictedAgentResponseAdapter(HmacSignatureService hmacSignatureService, RestTemplateBuilder builder) {
        this.hmacSignatureService = hmacSignatureService;
        this.restTemplate = builder
                .setConnectTimeout(Duration.ofSeconds(3))
                .setReadTimeout(Duration.ofSeconds(5))
                .build();
    }

    @Override
    public String getAdapterType() {
        return "RESTRICTED_AGENT_ADAPTER";
    }

    @Override
    public boolean supports(ResponseProposalRecord proposal) {
        return proposal.getExecutionMode() == ResponseExecutionMode.LIVE;
    }

    @Override
    public ResponseExecutionResult dispatch(ResponseProposalRecord proposal) {
        long startTime = System.currentTimeMillis();
        long timestamp = Instant.now().getEpochSecond();

        String payload = String.format("{\"actionUuid\":\"%s\",\"playbookCode\":\"%s\",\"target\":\"%s\"}",
                proposal.getProposalUuid(), proposal.getActionCode(), proposal.getTargetIdentifier());

        try {
            String signature = hmacSignatureService.signPayload(payload, timestamp);

            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.APPLICATION_JSON);
            headers.set("X-BlueOps-Signature", signature);
            headers.set("X-BlueOps-Timestamp", String.valueOf(timestamp));
            headers.set("X-BlueOps-ActionId", proposal.getProposalUuid());

            HttpEntity<String> entity = new HttpEntity<>(payload, headers);
            ResponseEntity<String> response = restTemplate.postForEntity(responseAgentUrl + "/api/v1/execute", entity, String.class);

            long duration = System.currentTimeMillis() - startTime;
            boolean isSuccess = response.getStatusCode().is2xxSuccessful();

            return new ResponseExecutionResult(
                    isSuccess,
                    response.getStatusCode().value(),
                    "RESTRICTED_AGENT",
                    isSuccess ? "Dispatched through agent successfully" : "Agent returned non-2xx status",
                    response.getBody(),
                    duration
            );
        } catch (Exception ex) {
            long duration = System.currentTimeMillis() - startTime;
            log.warn("[AGENT ADAPTER ERROR] Failed communicating with response agent: {}", ex.getMessage());
            return new ResponseExecutionResult(
                    false,
                    503,
                    "RESTRICTED_AGENT",
                    "Agent communication failure: " + ex.getMessage(),
                    "{\"error\":\"AGENT_UNAVAILABLE\",\"details\":\"" + ex.getMessage() + "\"}",
                    duration
            );
        }
    }
}
