package com.blueops.telemetry;

import com.blueops.correlation.CorrelationRecord;
import com.blueops.correlation.CorrelationService;
import com.blueops.entities.M5TestStubs;
import com.blueops.findings.FindingDto;
import com.blueops.findings.OpenSearchFindingAdapter;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.web.client.RestTemplateBuilder;
import org.springframework.http.MediaType;
import org.springframework.test.annotation.DirtiesContext;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import java.time.Instant;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest(properties = {
        "blueops.telemetry.ingest-api-key=test-fluentbit-key-2026",
        "blueops.demo.seed-findings=false"
})
@AutoConfigureMockMvc
@ActiveProfiles("dev")
@DirtiesContext(classMode = DirtiesContext.ClassMode.AFTER_EACH_TEST_METHOD)
class PipelineAndCorrelationIntegrationTest {

    private static final String VALID_INGEST_KEY = "test-fluentbit-key-2026";

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    @Test
    void testFluentBitAuthenticatedIngestAcrossSeparateRequestsCorrelatesAndPromotesIdempotently() throws Exception {
        String analystToken = loginAndGetAccessToken("analyst", "Analyst@BlueOps2026!");

        // 1. Operational finding store starts empty when demo seeding is off (default)
        mockMvc.perform(get("/api/v1/detections/findings")
                        .header("Authorization", "Bearer " + analystToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data.length()").value(0));

        // 2. Collector key authentication fails closed when missing, wrong, or used outside POST /api/v1/telemetry/ingest
        mockMvc.perform(post("/api/v1/telemetry/ingest")
                        .header("X-BlueOps-Ingest-Key", "wrong-key")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"hostname\":\"WIN-WORKSTATION-01\"}"))
                .andExpect(status().is4xxClientError());

        mockMvc.perform(get("/api/v1/detections/findings")
                        .header("X-BlueOps-Ingest-Key", VALID_INGEST_KEY))
                .andExpect(status().is4xxClientError());

        // 3. Separate Fluent Bit ingestion #1 (D009: Office spawning cmd.exe)
        String event1Payload = objectMapper.writeValueAsString(Map.of(
                "id", "fb-evt-001",
                "blueops.collector", "fluent-bit",
                "hostname", "WIN-WORKSTATION-01",
                "host_ip", "192.168.56.101",
                "ParentImage", "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE",
                "Image", "C:\\Windows\\System32\\cmd.exe",
                "CommandLine", "cmd.exe /c whoami",
                "username", "analyst.dev",
                "provider", "Sysmon",
                "EventID", 1
        ));

        MvcResult ingestRes1 = mockMvc.perform(post("/api/v1/telemetry/ingest")
                        .header("X-BlueOps-Ingest-Key", VALID_INGEST_KEY)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(event1Payload))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.normalized").value(1))
                .andReturn();
        JsonNode res1Json = objectMapper.readTree(ingestRes1.getResponse().getContentAsString());
        assertTrue(res1Json.get("findingsGenerated").asInt() >= 1, "Event 1 should trigger D009 finding");

        // Verify collector metadata & entity extraction persisted from Event 1
        mockMvc.perform(get("/api/v1/telemetry/events/fb-evt-001")
                        .header("Authorization", "Bearer " + analystToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.blueops.collector").value("fluent-bit"))
                .andExpect(jsonPath("$.blueops.normalizationStatus").value("success"));

        mockMvc.perform(get("/api/v1/entities?search=win-workstation-01")
                        .header("Authorization", "Bearer " + analystToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.content[0].canonicalId").value("host:win-workstation-01"));

        // 4. Separate Fluent Bit ingestion #2 (D008: Encoded PowerShell on same host) -> correlates across requests!
        String event2Payload = objectMapper.writeValueAsString(Map.of(
                "id", "fb-evt-002",
                "blueops.collector", "fluent-bit",
                "hostname", "WIN-WORKSTATION-01",
                "host_ip", "192.168.56.101",
                "ParentImage", "C:\\Windows\\System32\\cmd.exe",
                "Image", "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                "CommandLine", "powershell.exe -noni -w hidden -enc JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0AA==",
                "username", "analyst.dev",
                "provider", "Sysmon",
                "EventID", 1
        ));

        MvcResult ingestRes2 = mockMvc.perform(post("/api/v1/telemetry/ingest")
                        .header("X-BlueOps-Ingest-Key", VALID_INGEST_KEY)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(event2Payload))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.normalized").value(1))
                .andReturn();
        JsonNode res2Json = objectMapper.readTree(ingestRes2.getResponse().getContentAsString());
        assertTrue(res2Json.get("correlationsGenerated").asInt() >= 1,
                "Authoritative CorrelationService must correlate D009 + D008 across separate HTTP ingestions");

        // Verify legacy auto-incident duplication is retired (0 incidents before explicit promote)
        mockMvc.perform(get("/api/v1/incidents")
                        .header("Authorization", "Bearer " + analystToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data.totalElements").value(0));

        // 5. Inspect persisted correlation and test idempotent incident promotion
        MvcResult corrRes = mockMvc.perform(get("/api/v1/correlations")
                        .header("Authorization", "Bearer " + analystToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.content[0].ruleId").value("CORR-002"))
                .andReturn();
        long corrDbId = objectMapper.readTree(corrRes.getResponse().getContentAsString())
                .get("content").get(0).get("id").asLong();

        MvcResult promote1 = mockMvc.perform(post("/api/v1/correlations/" + corrDbId + "/promote")
                        .header("Authorization", "Bearer " + analystToken))
                .andExpect(status().isOk())
                .andReturn();
        long incidentId1 = objectMapper.readTree(promote1.getResponse().getContentAsString()).get("id").asLong();

        // Second promote call must be idempotent and return the same incident
        MvcResult promote2 = mockMvc.perform(post("/api/v1/correlations/" + corrDbId + "/promote")
                        .header("Authorization", "Bearer " + analystToken))
                .andExpect(status().isOk())
                .andReturn();
        long incidentId2 = objectMapper.readTree(promote2.getResponse().getContentAsString()).get("id").asLong();
        assertEquals(incidentId1, incidentId2, "Promoting an already promoted correlation must be idempotent");

        mockMvc.perform(get("/api/v1/incidents")
                        .header("Authorization", "Bearer " + analystToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data.totalElements").value(1));
    }

    @Test
    void testDemoSeededFindingsAreIsolatedAndNeverContaminateRealCorrelation() {
        OpenSearchFindingAdapter demoEnabledAdapter = new OpenSearchFindingAdapter(
                new RestTemplateBuilder(), "http://localhost:9200", "admin", "admin", false, true
        );
        // Demo findings exist only when explicitly opted-in, and operational view excludes them
        assertEquals(3, demoEnabledAdapter.fetchFindings().size());
        assertEquals(0, demoEnabledAdapter.fetchOperationalFindings().size());

        CorrelationService serviceWithDemoAdapter = new CorrelationService(
                new M5TestStubs.StubCorrelationRepository(),
                new M5TestStubs.StubCorrelationRuleRepository(),
                new M5TestStubs.StubCorrelationFindingRepository(),
                new M5TestStubs.StubCorrelationEntityRepository(),
                new M5TestStubs.StubEntityRepository(),
                null,
                demoEnabledAdapter
        );

        // Single real D004 finding on LAB-LNX-01 must NOT falsely correlate with demo-seeded FND-2026-001 (D001 on LAB-LNX-01)
        FindingDto realPrivExec = new FindingDto(
                "FND-REAL-1", "D004", "Privileged Execution", "HIGH",
                "Privilege Escalation", "T1548", "Sudo",
                "LNX-ASSET-001", "LAB-LNX-01", Instant.now(), "UNASSIGNED", "evt-real-1", Map.of()
        );
        List<CorrelationRecord> correlations = serviceWithDemoAdapter.evaluateAndPersist(List.of(realPrivExec));
        assertTrue(correlations.isEmpty(), "Demo findings must never join or trigger real correlations");
    }

    private String loginAndGetAccessToken(String username, String password) throws Exception {
        MvcResult res = mockMvc.perform(post("/api/v1/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"username\":\"" + username + "\",\"password\":\"" + password + "\"}"))
                .andExpect(status().isOk())
                .andReturn();
        return objectMapper.readTree(res.getResponse().getContentAsString())
                .get("data").get("accessToken").asText();
    }
}
