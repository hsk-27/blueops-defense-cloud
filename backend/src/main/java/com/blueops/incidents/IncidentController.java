package com.blueops.incidents;

import com.blueops.common.dto.ApiResponse;
import com.blueops.common.dto.PagedResponse;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Sort;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/v1/incidents")
@Tag(name = "Incidents", description = "SOC incident lifecycle management, triage, and timelines")
public class IncidentController {

    private final IncidentService incidentService;

    public IncidentController(IncidentService incidentService) {
        this.incidentService = incidentService;
    }

    @GetMapping
    @Operation(summary = "Query incidents with optional status and severity filtering")
    public ResponseEntity<ApiResponse<PagedResponse<IncidentDto>>> getIncidents(
            @RequestParam(required = false) IncidentStatus status,
            @RequestParam(required = false) IncidentSeverity severity,
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "15") int size,
            @RequestParam(defaultValue = "createdAt") String sortBy,
            @RequestParam(defaultValue = "desc") String direction) {

        Sort sort = direction.equalsIgnoreCase("asc") ? Sort.by(sortBy).ascending() : Sort.by(sortBy).descending();
        Page<IncidentDto> paged = incidentService.getIncidents(status, severity, PageRequest.of(page, size, sort));

        PagedResponse<IncidentDto> response = new PagedResponse<>(
                paged.getContent(), paged.getNumber(), paged.getSize(),
                paged.getTotalElements(), paged.getTotalPages(), paged.isLast()
        );
        return ResponseEntity.ok(ApiResponse.success(response));
    }

    @PostMapping
    @PreAuthorize("hasAnyRole('ADMIN', 'ANALYST')")
    @Operation(summary = "Create an incident from detected findings or manual analyst alert")
    public ResponseEntity<ApiResponse<IncidentDto>> createIncident(@Valid @RequestBody IncidentCreateRequest request, Authentication auth) {
        IncidentDto created = incidentService.createIncident(request, auth.getName());
        return ResponseEntity.status(HttpStatus.CREATED).body(ApiResponse.success("Incident created", created));
    }

    @GetMapping("/{id}")
    @Operation(summary = "Get detailed incident record")
    public ResponseEntity<ApiResponse<IncidentDto>> getIncidentById(@PathVariable Long id) {
        return ResponseEntity.ok(ApiResponse.success(incidentService.getIncidentById(id)));
    }

    @GetMapping("/{id}/timeline")
    @Operation(summary = "Get chronological investigation timeline of detections, actions, and notes")
    public ResponseEntity<ApiResponse<List<IncidentTimelineEntryDto>>> getTimeline(@PathVariable Long id) {
        return ResponseEntity.ok(ApiResponse.success(incidentService.getTimeline(id)));
    }

    @GetMapping("/{id}/findings")
    @Operation(summary = "Get associated OpenSearch findings for this incident")
    public ResponseEntity<ApiResponse<List<IncidentFinding>>> getFindings(@PathVariable Long id) {
        return ResponseEntity.ok(ApiResponse.success(incidentService.getIncidentFindings(id)));
    }

    @PostMapping("/{id}/notes")
    @PreAuthorize("hasAnyRole('ADMIN', 'ANALYST')")
    @Operation(summary = "Add an investigation note")
    public ResponseEntity<ApiResponse<Void>> addNote(@PathVariable Long id, @Valid @RequestBody IncidentNoteRequest request, Authentication auth) {
        incidentService.addNote(id, request, auth.getName());
        return ResponseEntity.ok(ApiResponse.success("Note added successfully", null));
    }

    @PutMapping("/{id}/assign")
    @PreAuthorize("hasAnyRole('ADMIN', 'ANALYST')")
    @Operation(summary = "Assign incident to a designated SOC analyst")
    public ResponseEntity<ApiResponse<IncidentDto>> assignIncident(@PathVariable Long id, @Valid @RequestBody IncidentAssignRequest request, Authentication auth) {
        IncidentDto updated = incidentService.assignIncident(id, request, auth.getName());
        return ResponseEntity.ok(ApiResponse.success("Incident assigned", updated));
    }

    @PutMapping("/{id}/status")
    @PreAuthorize("hasAnyRole('ADMIN', 'ANALYST')")
    @Operation(summary = "Transition incident lifecycle state (validated by state machine)")
    public ResponseEntity<ApiResponse<IncidentDto>> updateStatus(@PathVariable Long id, @Valid @RequestBody IncidentStatusUpdateRequest request, Authentication auth) {
        IncidentDto updated = incidentService.updateStatus(id, request, auth.getName());
        return ResponseEntity.ok(ApiResponse.success("Status updated", updated));
    }

    @PostMapping("/{id}/reopen")
    @PreAuthorize("hasAnyRole('ADMIN', 'ANALYST')")
    @Operation(summary = "Reopen a previously resolved or false-positive incident")
    public ResponseEntity<ApiResponse<IncidentDto>> reopenIncident(@PathVariable Long id, @RequestParam(required = false) String reason, Authentication auth) {
        IncidentDto reopened = incidentService.reopenIncident(id, reason, auth.getName());
        return ResponseEntity.ok(ApiResponse.success("Incident reopened", reopened));
    }
}
