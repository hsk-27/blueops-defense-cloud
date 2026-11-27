package com.blueops.security;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("dev")
class JwtAndSoarSecurityIntegrationTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    @Test
    void testJwtAccessAndRefreshTokenTypeSeparation() throws Exception {
        String loginBody = "{\"username\":\"analyst\",\"password\":\"Analyst@BlueOps2026!\"}";
        MvcResult loginResult = mockMvc.perform(post("/api/v1/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(loginBody))
                .andExpect(status().isOk())
                .andReturn();

        JsonNode loginData = objectMapper.readTree(loginResult.getResponse().getContentAsString()).get("data");
        String accessToken = loginData.get("accessToken").asText();
        String refreshToken = loginData.get("refreshToken").asText();

        // 1. Access token succeeds on protected API route
        mockMvc.perform(get("/api/v1/auth/me")
                        .header("Authorization", "Bearer " + accessToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data.username").value("analyst"));

        // 2. Refresh token must be rejected on protected API routes
        mockMvc.perform(get("/api/v1/auth/me")
                        .header("Authorization", "Bearer " + refreshToken))
                .andExpect(status().is4xxClientError());

        mockMvc.perform(get("/api/v1/response/soar/catalog")
                        .header("Authorization", "Bearer " + refreshToken))
                .andExpect(status().is4xxClientError());

        // 3. Access token must be rejected on /api/v1/auth/refresh
        mockMvc.perform(post("/api/v1/auth/refresh")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"refreshToken\":\"" + accessToken + "\"}"))
                .andExpect(status().isUnauthorized());

        // 4. Refresh token works legitimately on /api/v1/auth/refresh
        mockMvc.perform(post("/api/v1/auth/refresh")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"refreshToken\":\"" + refreshToken + "\"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data.accessToken").isNotEmpty());
    }

    @Test
    @WithMockUser(username = "viewer", roles = {"VIEWER"})
    void testViewerIsReadOnlyOnSoarEndpoints() throws Exception {
        mockMvc.perform(get("/api/v1/response/soar/catalog"))
                .andExpect(status().isOk());
        mockMvc.perform(get("/api/v1/response/soar/targets"))
                .andExpect(status().isOk());
        mockMvc.perform(get("/api/v1/response/soar/proposals"))
                .andExpect(status().isOk());

        String reqBody = "{\"actionCode\":\"ACT-001\",\"targetIdentifier\":\"198.51.100.24\",\"executionMode\":\"SIMULATION\"}";
        mockMvc.perform(post("/api/v1/response/soar/policy-preview")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(reqBody))
                .andExpect(status().isForbidden());
        mockMvc.perform(post("/api/v1/response/soar/proposals")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(reqBody))
                .andExpect(status().isForbidden());
        mockMvc.perform(post("/api/v1/response/soar/proposals/1/cancel")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{}"))
                .andExpect(status().isForbidden());
        mockMvc.perform(post("/api/v1/response/soar/proposals/1/approve")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{}"))
                .andExpect(status().isForbidden());
        mockMvc.perform(post("/api/v1/response/soar/proposals/1/deny")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{}"))
                .andExpect(status().isForbidden());
        mockMvc.perform(post("/api/v1/response/soar/proposals/1/execute"))
                .andExpect(status().isForbidden());
    }

    @Test
    @WithMockUser(username = "analyst", roles = {"ANALYST"})
    void testAnalystCanPreviewProposeCancelButCannotApproveDenyOrExecute() throws Exception {
        String reqBody = "{\"actionCode\":\"ACT-001\",\"targetIdentifier\":\"198.51.100.24\",\"executionMode\":\"SIMULATION\"}";
        mockMvc.perform(post("/api/v1/response/soar/policy-preview")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(reqBody))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.outcome").value("REQUIRE_APPROVAL"));

        MvcResult createdResult = mockMvc.perform(post("/api/v1/response/soar/proposals")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(reqBody))
                .andExpect(status().isCreated())
                .andReturn();
        long proposalId = objectMapper.readTree(createdResult.getResponse().getContentAsString()).get("id").asLong();

        mockMvc.perform(post("/api/v1/response/soar/proposals/" + proposalId + "/approve")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{}"))
                .andExpect(status().isForbidden());
        mockMvc.perform(post("/api/v1/response/soar/proposals/" + proposalId + "/deny")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{}"))
                .andExpect(status().isForbidden());
        mockMvc.perform(post("/api/v1/response/soar/proposals/" + proposalId + "/execute"))
                .andExpect(status().isForbidden());
        mockMvc.perform(post("/api/v1/response/soar/proposals/" + proposalId + "/cancel")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"reason\":\"No longer needed\"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("CANCELLED"));
    }

    @Test
    void testAdminCanApproveExecuteButRespectsSeparationOfDuties() throws Exception {
        String analystToken = loginAndGetAccessToken("analyst", "Analyst@BlueOps2026!");
        String adminToken = loginAndGetAccessToken("admin", "Admin@BlueOps2026!");

        // Analyst creates HIGH-risk proposal (ACT-002), Admin approves and executes
        String analystReq = "{\"actionCode\":\"ACT-002\",\"targetIdentifier\":\"CORP\\\\analyst\",\"executionMode\":\"SIMULATION\"}";
        MvcResult analystProposalRes = mockMvc.perform(post("/api/v1/response/soar/proposals")
                        .header("Authorization", "Bearer " + analystToken)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(analystReq))
                .andExpect(status().isCreated())
                .andReturn();
        long analystProposalId = objectMapper.readTree(analystProposalRes.getResponse().getContentAsString()).get("id").asLong();

        mockMvc.perform(post("/api/v1/response/soar/proposals/" + analystProposalId + "/approve")
                        .header("Authorization", "Bearer " + adminToken)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"reason\":\"Approved after analyst investigation\",\"executeImmediately\":false}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("APPROVED"));

        mockMvc.perform(post("/api/v1/response/soar/proposals/" + analystProposalId + "/execute")
                        .header("Authorization", "Bearer " + adminToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("SIMULATED"))
                .andExpect(jsonPath("$.verification.status").value("SIMULATION_ONLY"));

        // Admin cannot self-approve own HIGH-risk proposal (SoD still enforced)
        MvcResult adminProposalRes = mockMvc.perform(post("/api/v1/response/soar/proposals")
                        .header("Authorization", "Bearer " + adminToken)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(analystReq))
                .andExpect(status().isCreated())
                .andReturn();
        long adminProposalId = objectMapper.readTree(adminProposalRes.getResponse().getContentAsString()).get("id").asLong();

        mockMvc.perform(post("/api/v1/response/soar/proposals/" + adminProposalId + "/approve")
                        .header("Authorization", "Bearer " + adminToken)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"reason\":\"Self approve\"}"))
                .andExpect(status().isBadRequest());
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
