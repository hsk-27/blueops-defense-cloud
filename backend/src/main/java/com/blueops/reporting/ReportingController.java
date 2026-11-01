package com.blueops.reporting;

import com.blueops.common.dto.ApiResponse;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RestController
@RequestMapping("/api/v1/reports")
@Tag(name = "Reports & Analytics", description = "SOC overview metrics, MTTD/MTTR, and MITRE ATT&CK coverage")
public class ReportingController {

    private final ReportingService reportingService;

    public ReportingController(ReportingService reportingService) {
        this.reportingService = reportingService;
    }

    @GetMapping("/overview")
    @Operation(summary = "Get high-level SOC operational metrics and health status")
    public ResponseEntity<ApiResponse<SocOverviewMetricsDto>> getSocOverview() {
        return ResponseEntity.ok(ApiResponse.success(reportingService.getSocOverviewMetrics()));
    }

    @GetMapping("/attack-coverage")
    @Operation(summary = "Get MITRE ATT&CK technique detection coverage matrix")
    public ResponseEntity<ApiResponse<Map<String, Object>>> getAttackCoverage() {
        return ResponseEntity.ok(ApiResponse.success(reportingService.getAttackCoverage()));
    }
}
