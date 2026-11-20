package com.blueops.incidents;

import java.time.Instant;
import java.util.Map;

/**
 * Coherent Evidence Reference Model (M4 - Section 8).
 * Links an Incident directly to underlying findings, triggering normalized events,
 * and immutable raw provenance payloads without duplicating data.
 */
public class IncidentEvidenceDto {
    private String evidenceId;
    private String type; // TELEMETRY_EVENT, DETECTION_RULE_MATCH, HOST_CONTEXT
    private String findingId;
    private String ruleId;
    private String ruleName;
    private String severity;
    private Instant timestamp;
    private String provider;
    private String host;
    private String sourceIp;
    private String user;
    private String process;
    private String rawPayload;
    private Map<String, Object> normalizedAttributes;

    public IncidentEvidenceDto() {}

    public IncidentEvidenceDto(String evidenceId, String type, String findingId, String ruleId,
                               String ruleName, String severity, Instant timestamp, String provider,
                               String host, String sourceIp, String user, String process,
                               String rawPayload, Map<String, Object> normalizedAttributes) {
        this.evidenceId = evidenceId;
        this.type = type;
        this.findingId = findingId;
        this.ruleId = ruleId;
        this.ruleName = ruleName;
        this.severity = severity;
        this.timestamp = timestamp;
        this.provider = provider;
        this.host = host;
        this.sourceIp = sourceIp;
        this.user = user;
        this.process = process;
        this.rawPayload = rawPayload;
        this.normalizedAttributes = normalizedAttributes;
    }

    public String getEvidenceId() { return evidenceId; }
    public void setEvidenceId(String evidenceId) { this.evidenceId = evidenceId; }

    public String getType() { return type; }
    public void setType(String type) { this.type = type; }

    public String getFindingId() { return findingId; }
    public void setFindingId(String findingId) { this.findingId = findingId; }

    public String getRuleId() { return ruleId; }
    public void setRuleId(String ruleId) { this.ruleId = ruleId; }

    public String getRuleName() { return ruleName; }
    public void setRuleName(String ruleName) { this.ruleName = ruleName; }

    public String getSeverity() { return severity; }
    public void setSeverity(String severity) { this.severity = severity; }

    public Instant getTimestamp() { return timestamp; }
    public void setTimestamp(Instant timestamp) { this.timestamp = timestamp; }

    public String getProvider() { return provider; }
    public void setProvider(String provider) { this.provider = provider; }

    public String getHost() { return host; }
    public void setHost(String host) { this.host = host; }

    public String getSourceIp() { return sourceIp; }
    public void setSourceIp(String sourceIp) { this.sourceIp = sourceIp; }

    public String getUser() { return user; }
    public void setUser(String user) { this.user = user; }

    public String getProcess() { return process; }
    public void setProcess(String process) { this.process = process; }

    public String getRawPayload() { return rawPayload; }
    public void setRawPayload(String rawPayload) { this.rawPayload = rawPayload; }

    public Map<String, Object> getNormalizedAttributes() { return normalizedAttributes; }
    public void setNormalizedAttributes(Map<String, Object> normalizedAttributes) { this.normalizedAttributes = normalizedAttributes; }
}
