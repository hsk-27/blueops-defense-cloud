package com.blueops.advisory;

import com.blueops.common.dto.ApiResponse;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Collections;
import java.util.List;

@RestController
@RequestMapping("/api/v1/advisory")
@Tag(name = "Authoritative Advisory System", description = "Contextual next-step recommendations derived strictly from NIST SP 800-61r2, CISA, MITRE, and SANS")
public class AdvisoryController {

    private final IncidentAdvisoryService advisoryService;

    public AdvisoryController(IncidentAdvisoryService advisoryService) {
        this.advisoryService = advisoryService;
    }

    @GetMapping("/incidents/{incidentId}/recommendations")
    @Operation(summary = "Get authoritative incident response recommendations for a specific incident")
    public ResponseEntity<ApiResponse<List<IncidentRecommendationDto>>> getIncidentRecommendations(@PathVariable Long incidentId) {
        List<IncidentRecommendationDto> recommendations = advisoryService.generateRecommendations(incidentId);
        return ResponseEntity.ok(ApiResponse.success(recommendations));
    }

    @PostMapping("/analyze")
    @Operation(summary = "Ad-hoc analysis and authoritative recommendation generation for custom detection telemetry")
    public ResponseEntity<ApiResponse<List<IncidentRecommendationDto>>> analyzeAdHoc(@RequestBody AdvisoryAnalysisRequest request) {
        List<IncidentRecommendationDto> recommendations = advisoryService.analyzeAdHoc(
                request.getStatus(),
                request.getSeverity(),
                request.getRuleCodes() != null ? request.getRuleCodes() : Collections.emptySet(),
                request.getTechniqueIds() != null ? request.getTechniqueIds() : Collections.emptySet(),
                request.getAssetTarget() != null ? request.getAssetTarget() : "LAB-HOST",
                request.getAttackerIp(),
                request.getUsername()
        );
        return ResponseEntity.ok(ApiResponse.success(recommendations));
    }
}
