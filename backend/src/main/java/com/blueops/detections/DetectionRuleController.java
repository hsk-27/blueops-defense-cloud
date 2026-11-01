package com.blueops.detections;

import com.blueops.common.dto.ApiResponse;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/v1/detections")
@Tag(name = "Detections", description = "Sigma detection rules and analytics management")
public class DetectionRuleController {

    private final DetectionRuleService ruleService;

    public DetectionRuleController(DetectionRuleService ruleService) {
        this.ruleService = ruleService;
    }

    @GetMapping
    @Operation(summary = "List all detection rules")
    public ResponseEntity<ApiResponse<List<DetectionRuleDto>>> getAllRules() {
        return ResponseEntity.ok(ApiResponse.success(ruleService.getAllRules()));
    }

    @GetMapping("/{id}")
    @Operation(summary = "Get detection rule details")
    public ResponseEntity<ApiResponse<DetectionRuleDto>> getRuleById(@PathVariable Long id) {
        return ResponseEntity.ok(ApiResponse.success(ruleService.getRuleById(id)));
    }

    @PutMapping("/{id}/status")
    @PreAuthorize("hasRole('ADMIN')")
    @Operation(summary = "Enable or disable a detection rule")
    public ResponseEntity<ApiResponse<DetectionRuleDto>> updateStatus(@PathVariable Long id, @RequestParam String status) {
        DetectionRuleDto updated = ruleService.updateRuleStatus(id, status);
        return ResponseEntity.ok(ApiResponse.success("Rule status updated", updated));
    }

    @GetMapping("/summary")
    @Operation(summary = "Get high-level summary of detection coverage and rule states")
    public ResponseEntity<ApiResponse<Map<String, Object>>> getSummary() {
        return ResponseEntity.ok(ApiResponse.success(ruleService.getDetectionsSummary()));
    }
}
