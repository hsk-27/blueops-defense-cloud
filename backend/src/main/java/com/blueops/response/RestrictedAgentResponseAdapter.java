package com.blueops.response;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
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
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;

@Component
public class RestrictedAgentResponseAdapter implements ResponseAdapter {

    private static final Logger log = LoggerFactory.getLogger(RestrictedAgentResponseAdapter.class);

    public record AgentActionMapping(String agentAction, String playbookCode) {}

    private static final Map<String, AgentActionMapping> SUPPORTED_ACTION_MAP = Map.ofEntries(
            Map.entry("ACT-001", new AgentActionMapping("BLOCK_IP", "P001")),
            Map.entry("P001", new AgentActionMapping("BLOCK_IP", "P001")),
            Map.entry("ACT-002", new AgentActionMapping("DISABLE_USER", "P002")),
            Map.entry("P002", new AgentActionMapping("DISABLE_USER", "P002")),
            Map.entry("ACT-003", new AgentActionMapping("ISOLATE_HOST", "P003")),
            Map.entry("P003", new AgentActionMapping("ISOLATE_HOST", "P003")),
            Map.entry("ACT-004", new AgentActionMapping("RESTORE_IP", "P004")),
            Map.entry("P004", new AgentActionMapping("RESTORE_IP", "P004")),
            Map.entry("ACT-005", new AgentActionMapping("ENABLE_USER", "P005")),
            Map.entry("P005", new AgentActionMapping("ENABLE_USER", "P005")),
            Map.entry("ACT-006", new AgentActionMapping("RECONNECT_HOST", "P006")),
            Map.entry("P006", new AgentActionMapping("RECONNECT_HOST", "P006")),
            Map.entry("ACT-007", new AgentActionMapping("COLLECT_EVIDENCE", "P007")),
            Map.entry("P007", new AgentActionMapping("COLLECT_EVIDENCE", "P007"))
    );

    private final HmacSignatureService hmacSignatureService;
    private final RestTemplate restTemplate;
    private final ObjectMapper objectMapper;

    @Value("${blueops.response-agent.url:http://localhost:5000}")
    private String responseAgentUrl;

    public RestrictedAgentResponseAdapter(HmacSignatureService hmacSignatureService, RestTemplateBuilder builder) {
        this(hmacSignatureService, builder, new ObjectMapper());
    }

    @Autowired
    public RestrictedAgentResponseAdapter(
            HmacSignatureService hmacSignatureService,
            RestTemplateBuilder builder,
            ObjectMapper objectMapper) {
        this(
                hmacSignatureService,
                builder.setConnectTimeout(Duration.ofSeconds(3))
                        .setReadTimeout(Duration.ofSeconds(5))
                        .build(),
                objectMapper
        );
    }

    RestrictedAgentResponseAdapter(
            HmacSignatureService hmacSignatureService,
            RestTemplate restTemplate,
            ObjectMapper objectMapper) {
        this.hmacSignatureService = hmacSignatureService;
        this.restTemplate = restTemplate;
        this.objectMapper = objectMapper;
    }

    public static Optional<AgentActionMapping> resolveAgentAction(String actionCode) {
        if (actionCode == null || actionCode.isBlank()) {
            return Optional.empty();
        }
        return Optional.ofNullable(SUPPORTED_ACTION_MAP.get(actionCode.trim().toUpperCase(Locale.ROOT)));
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

        Optional<AgentActionMapping> mappingOpt = resolveAgentAction(proposal.getActionCode());
        if (mappingOpt.isEmpty()) {
            String errorMsg = String.format("Action code '%s' is not supported by the restricted response agent.", proposal.getActionCode());
            log.warn("[UNSUPPORTED ACTION REJECTED] {}", errorMsg);
            return new ResponseExecutionResult(
                    false,
                    501,
                    "UNSUPPORTED_ACTION",
                    errorMsg,
                    serializeErrorPayload("UNSUPPORTED_ACTION", errorMsg, proposal.getActionCode()),
                    System.currentTimeMillis() - startTime
            );
        }

        AgentActionMapping mapping = mappingOpt.get();

        try {
            Map<String, Object> body = new LinkedHashMap<>();
            body.put("actionUuid", proposal.getProposalUuid());
            body.put("actionCode", proposal.getActionCode());
            body.put("playbookCode", mapping.playbookCode());
            body.put("action", mapping.agentAction());
            body.put("target", proposal.getTargetIdentifier());

            String payload = objectMapper.writeValueAsString(body);
            String signature = hmacSignatureService.signPayload(payload, timestamp);

            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.APPLICATION_JSON);
            headers.set("X-BlueOps-Signature", signature);
            headers.set("X-BlueOps-Timestamp", String.valueOf(timestamp));
            headers.set("X-BlueOps-ActionId", proposal.getProposalUuid());

            HttpEntity<String> entity = new HttpEntity<>(payload, headers);
            ResponseEntity<String> response = restTemplate.postForEntity(responseAgentUrl + "/api/v1/execute", entity, String.class);

            long duration = System.currentTimeMillis() - startTime;
            boolean httpSuccess = response.getStatusCode().is2xxSuccessful();
            String responseBody = response.getBody();

            boolean agentReportedSuccess = httpSuccess;
            String reportedMode = "RESTRICTED_AGENT";
            String message = httpSuccess ? "Dispatched through response agent" : "Agent returned non-2xx status";

            if (responseBody != null && !responseBody.isBlank()) {
                try {
                    JsonNode json = objectMapper.readTree(responseBody);
                    if (json.hasNonNull("mode")) {
                        reportedMode = json.get("mode").asText();
                    }
                    if (json.hasNonNull("status")) {
                        String statusText = json.get("status").asText("");
                        if ("FAILED".equalsIgnoreCase(statusText) || "ERROR".equalsIgnoreCase(statusText)) {
                            agentReportedSuccess = false;
                        }
                    }
                    if (json.hasNonNull("remediation")) {
                        message = json.get("remediation").asText();
                    } else if (json.hasNonNull("message")) {
                        message = json.get("message").asText();
                    }
                } catch (Exception ignored) {
                    // Non-JSON response body; preserve raw response status & body
                }
            }

            return new ResponseExecutionResult(
                    agentReportedSuccess,
                    response.getStatusCode().value(),
                    reportedMode,
                    message,
                    responseBody != null ? responseBody : "{}",
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
                    serializeErrorPayload("AGENT_UNAVAILABLE", ex.getMessage(), proposal.getActionCode()),
                    duration
            );
        }
    }

    private String serializeErrorPayload(String errorCode, String details, String actionCode) {
        try {
            Map<String, Object> err = new LinkedHashMap<>();
            err.put("error", errorCode);
            err.put("actionCode", actionCode);
            err.put("details", details);
            return objectMapper.writeValueAsString(err);
        } catch (Exception e) {
            return "{\"error\":\"" + errorCode + "\"}";
        }
    }
}
