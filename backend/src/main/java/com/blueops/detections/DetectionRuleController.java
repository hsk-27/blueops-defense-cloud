package com.blueops.detections;

import com.blueops.common.dto.ApiResponse;
import com.blueops.detections.sigma.SigmaRuleDefinition;
import com.blueops.detections.sigma.SigmaRuleRegistry;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/v1/detections")
@Tag(name = "Detections", description = "Sigma detection rules and analytics management")
public class DetectionRuleController {

    private final DetectionRuleService ruleService;
    private final SigmaRuleRegistry sigmaRegistry;

    @Autowired
    public DetectionRuleController(DetectionRuleService ruleService, @Autowired(required = false) SigmaRuleRegistry sigmaRegistry) {
        this.ruleService = ruleService;
        this.sigmaRegistry = sigmaRegistry;
    }

    public DetectionRuleController(DetectionRuleService ruleService) {
        this(ruleService, null);
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
        Map<String, Object> summary = new HashMap<>(ruleService.getDetectionsSummary());
        if (sigmaRegistry != null) {
            summary.put("dynamicSigmaLoadedCount", sigmaRegistry.getLoadedRuleCount());
        }
        return ResponseEntity.ok(ApiResponse.success(summary));
    }

    @GetMapping("/compatibility")
    @Operation(summary = "Get declared Sigma detection engine compatibility profile and supported capabilities")
    public ResponseEntity<ApiResponse<Map<String, Object>>> getSigmaCompatibilityProfile() {
        Map<String, Object> profile = new HashMap<>();
        profile.put("engineName", "BlueOps Dynamic Sigma Engine v1.2");
        profile.put("conditionGrammar", List.of("and", "or", "not", "parentheses", "1 of selection*", "all of selection*", "1 of them"));
        profile.put("fieldModifiersSupported", List.of("contains", "startswith", "endswith", "re", "all"));
        profile.put("aggregationsSupported", List.of("count(event.id) by <entity> > N", "count(user.name) by <entity> > N", "selection_fail and selection_success by <entity>"));
        profile.put("slidingWindowEngine", "SigmaAggregationEngine (Active, Thread-Safe Sliding Window)");
        profile.put("supportedLogsources", List.of("windows/sysmon", "linux/auditd", "network/suricata"));
        profile.put("unsupportedConstructs", List.of("near", "timeframe across distinct logsources", "min/max/avg statistical math aggregations"));
        profile.put("activeRuleCount", sigmaRegistry != null ? sigmaRegistry.getLoadedRuleCount() : 0);
        return ResponseEntity.ok(ApiResponse.success(profile));
    }

    @GetMapping("/sigma-catalog")
    @Operation(summary = "List all dynamically parsed declarative Sigma YAML rules")
    public ResponseEntity<ApiResponse<List<SigmaRuleDefinition>>> getSigmaCatalog() {
        if (sigmaRegistry == null) {
            return ResponseEntity.ok(ApiResponse.success("Sigma registry uninitialized", List.of()));
        }
        return ResponseEntity.ok(ApiResponse.success(sigmaRegistry.getAllRules()));
    }

    @PostMapping("/reload")
    @PreAuthorize("hasRole('ADMIN')")
    @Operation(summary = "Reload all Sigma detection rule YAML definitions from disk at runtime")
    public ResponseEntity<ApiResponse<Map<String, Object>>> reloadSigmaRules() {
        if (sigmaRegistry == null) {
            return ResponseEntity.badRequest().body(ApiResponse.error("Sigma registry not available"));
        }
        int count = sigmaRegistry.reloadRules();
        Map<String, Object> result = Map.of(
                "reloadedCount", count,
                "status", "SUCCESS",
                "message", "Successfully reloaded " + count + " Sigma detection rules from YAML storage."
        );
        return ResponseEntity.ok(ApiResponse.success(result));
    }
}
