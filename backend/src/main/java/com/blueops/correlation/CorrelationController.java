package com.blueops.correlation;

import com.blueops.common.dto.PagedResponse;
import com.blueops.incidents.IncidentDto;
import com.blueops.incidents.IncidentSeverity;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/v1/correlations")
public class CorrelationController {

    private final CorrelationService correlationService;

    public CorrelationController(CorrelationService correlationService) {
        this.correlationService = correlationService;
    }

    @GetMapping
    @PreAuthorize("hasAnyRole('ADMIN', 'ANALYST', 'VIEWER')")
    public ResponseEntity<PagedResponse<CorrelationDto>> getCorrelations(
            @RequestParam(required = false) IncidentSeverity severity,
            @RequestParam(required = false) CorrelationStatus status,
            @RequestParam(required = false) String query,
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "20") int size) {
        return ResponseEntity.ok(correlationService.getCorrelations(severity, status, query, page, size));
    }

    @GetMapping("/{id}")
    @PreAuthorize("hasAnyRole('ADMIN', 'ANALYST', 'VIEWER')")
    public ResponseEntity<CorrelationDto> getCorrelationById(@PathVariable Long id) {
        return ResponseEntity.ok(correlationService.getCorrelationById(id));
    }

    @GetMapping("/rules")
    @PreAuthorize("hasAnyRole('ADMIN', 'ANALYST', 'VIEWER')")
    public ResponseEntity<List<CorrelationRuleDto>> getCorrelationRules() {
        return ResponseEntity.ok(correlationService.getCorrelationRules());
    }

    @PatchMapping("/{id}/status")
    @PreAuthorize("hasAnyRole('ADMIN', 'ANALYST')")
    public ResponseEntity<CorrelationDto> updateStatus(
            @PathVariable Long id,
            @RequestParam CorrelationStatus status) {
        return ResponseEntity.ok(correlationService.updateStatus(id, status));
    }

    @PostMapping("/{id}/promote")
    @PreAuthorize("hasAnyRole('ADMIN', 'ANALYST')")
    public ResponseEntity<IncidentDto> promoteToIncident(
            @PathVariable Long id,
            Authentication authentication) {
        String username = authentication != null ? authentication.getName() : "analyst";
        return ResponseEntity.ok(correlationService.promoteToIncident(id, username));
    }
}
