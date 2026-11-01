package com.blueops.findings;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.web.client.RestTemplateBuilder;
import org.springframework.http.*;
import org.springframework.stereotype.Component;
import org.springframework.web.client.ResourceAccessException;
import org.springframework.web.client.RestTemplate;

import java.time.Duration;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

@Component
public class OpenSearchFindingAdapter {

    private static final Logger log = LoggerFactory.getLogger(OpenSearchFindingAdapter.class);

    private final RestTemplate restTemplate;
    private final String opensearchUri;
    private final boolean enabled;

    // In-memory finding cache & fallback store for resilient operation
    private final Map<String, FindingDto> findingsStore = new ConcurrentHashMap<>();

    public OpenSearchFindingAdapter(
            RestTemplateBuilder builder,
            @Value("${blueops.opensearch.uri:http://localhost:9200}") String opensearchUri,
            @Value("${blueops.opensearch.username:admin}") String username,
            @Value("${blueops.opensearch.password:admin}") String password,
            @Value("${blueops.opensearch.enabled:true}") boolean enabled) {
        this.opensearchUri = opensearchUri;
        this.enabled = enabled;
        this.restTemplate = builder
                .setConnectTimeout(Duration.ofSeconds(3))
                .setReadTimeout(Duration.ofSeconds(5))
                .basicAuthentication(username, password)
                .build();

        seedInitialDemonstrationFindings();
    }

    public List<FindingDto> fetchFindings() {
        if (!enabled) {
            return new ArrayList<>(findingsStore.values());
        }

        try {
            String url = opensearchUri + "/blueops-findings-*/_search?size=100&sort=@timestamp:desc";
            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.APPLICATION_JSON);
            HttpEntity<String> entity = new HttpEntity<>("{\"query\":{\"match_all\":{}}}", headers);

            ResponseEntity<Map> response = restTemplate.exchange(url, HttpMethod.POST, entity, Map.class);
            if (response.getStatusCode().is2xxSuccessful() && response.getBody() != null) {
                List<FindingDto> remoteFindings = parseOpenSearchResponse(response.getBody());
                for (FindingDto f : remoteFindings) {
                    findingsStore.put(f.getFindingId(), f);
                }
            }
        } catch (ResourceAccessException ex) {
            log.warn("OpenSearch cluster is currently unreachable: {}. Serving from local finding store.", ex.getMessage());
        } catch (Exception ex) {
            log.error("Failed to fetch findings from OpenSearch: {}", ex.getMessage());
        }

        return new ArrayList<>(findingsStore.values());
    }

    public void registerFinding(FindingDto finding) {
        findingsStore.put(finding.getFindingId(), finding);
        if (enabled) {
            try {
                String url = opensearchUri + "/blueops-findings-lab/_doc/" + finding.getFindingId();
                HttpHeaders headers = new HttpHeaders();
                headers.setContentType(MediaType.APPLICATION_JSON);
                restTemplate.exchange(url, HttpMethod.PUT, new HttpEntity<>(finding, headers), Void.class);
            } catch (Exception ex) {
                log.debug("Could not push finding to remote OpenSearch directly: {}", ex.getMessage());
            }
        }
    }

    public Optional<FindingDto> getFindingById(String findingId) {
        return Optional.ofNullable(findingsStore.get(findingId));
    }

    @SuppressWarnings("unchecked")
    private List<FindingDto> parseOpenSearchResponse(Map<String, Object> body) {
        List<FindingDto> list = new ArrayList<>();
        try {
            Map<String, Object> hitsObj = (Map<String, Object>) body.get("hits");
            if (hitsObj != null) {
                List<Map<String, Object>> hits = (List<Map<String, Object>>) hitsObj.get("hits");
                if (hits != null) {
                    for (Map<String, Object> hit : hits) {
                        Map<String, Object> src = (Map<String, Object>) hit.get("_source");
                        if (src != null) {
                            FindingDto dto = new FindingDto();
                            dto.setFindingId((String) src.getOrDefault("finding_id", (String) hit.get("_id")));
                            dto.setRuleId((String) src.get("rule_id"));
                            dto.setRuleName((String) src.get("rule_name"));
                            dto.setRuleSeverity((String) src.get("rule_severity"));
                            dto.setMitreTactic((String) src.get("mitre_tactic"));
                            dto.setMitreTechniqueId((String) src.get("mitre_technique_id"));
                            dto.setMitreTechniqueName((String) src.get("mitre_technique_name"));
                            dto.setAssetId((String) src.get("asset_id"));
                            dto.setAssetName((String) src.get("asset_name"));
                            dto.setStatus((String) src.getOrDefault("status", "UNASSIGNED"));
                            dto.setRelatedDocId((String) src.get("related_doc_ids"));
                            dto.setTimestamp(Instant.now());
                            list.add(dto);
                        }
                    }
                }
            }
        } catch (Exception ex) {
            log.error("Error parsing OpenSearch response: {}", ex.getMessage());
        }
        return list;
    }

    private void seedInitialDemonstrationFindings() {
        FindingDto f1 = new FindingDto(
                "FND-2026-001", "D001", "Repeated SSH Authentication Failures", "MEDIUM",
                "Credential Access", "T1110.001", "Password Guessing",
                "LNX-ASSET-001", "LAB-LNX-01", Instant.now().minusSeconds(1800),
                "UNASSIGNED", "DOC-OS-001",
                Map.of("sourceIp", "198.51.100.24", "targetUser", "root", "failureCount", 8)
        );

        FindingDto f2 = new FindingDto(
                "FND-2026-002", "D008", "Suspicious PowerShell Execution", "HIGH",
                "Execution", "T1059.001", "PowerShell",
                "WIN-ASSET-001", "LAB-WIN-01", Instant.now().minusSeconds(900),
                "UNASSIGNED", "DOC-OS-002",
                Map.of("commandLine", "powershell.exe -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA...", "pid", 4812, "parent", "cmd.exe")
        );

        FindingDto f3 = new FindingDto(
                "FND-2026-003", "D015", "Known IOC Communication", "HIGH",
                "Command and Control", "T1071", "Application Layer Protocol",
                "NET-ASSET-001", "LAB-FW-01", Instant.now().minusSeconds(300),
                "UNASSIGNED", "DOC-OS-003",
                Map.of("matchedIoc", "198.51.100.24", "destinationPort", 4444, "protocol", "TCP")
        );

        findingsStore.put(f1.getFindingId(), f1);
        findingsStore.put(f2.getFindingId(), f2);
        findingsStore.put(f3.getFindingId(), f3);
    }
}
