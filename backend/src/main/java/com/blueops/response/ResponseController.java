package com.blueops.response;

import com.blueops.common.dto.ApiResponse;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/v1/response")
@Tag(name = "Response Orchestration", description = "Constrained, auditable, reversible incident response playbooks")
public class ResponseController {

    private final ResponseOrchestrationService responseService;

    public ResponseController(ResponseOrchestrationService responseService) {
        this.responseService = responseService;
    }

    @GetMapping("/playbooks")
    @Operation(summary = "List all available response playbooks")
    public ResponseEntity<ApiResponse<List<ResponsePlaybook>>> getPlaybooks() {
        return ResponseEntity.ok(ApiResponse.success(responseService.getPlaybooks()));
    }

    @GetMapping("/playbooks/{code}")
    @Operation(summary = "Get specific playbook configuration")
    public ResponseEntity<ApiResponse<ResponsePlaybook>> getPlaybook(@PathVariable String code) {
        return ResponseEntity.ok(ApiResponse.success(responseService.getPlaybook(code)));
    }

    @PostMapping("/actions")
    @PreAuthorize("hasAnyRole('ADMIN', 'ANALYST')")
    @Operation(summary = "Request execution of a response playbook")
    public ResponseEntity<ApiResponse<ResponseActionDto>> requestAction(@Valid @RequestBody ResponseActionRequestDto request, Authentication auth) {
        ResponseActionDto action = responseService.requestAction(request, auth.getName());
        return ResponseEntity.status(HttpStatus.CREATED).body(ApiResponse.success("Response action requested", action));
    }

    @GetMapping("/actions")
    @Operation(summary = "List recent response action requests")
    public ResponseEntity<ApiResponse<List<ResponseActionDto>>> getRecentActions() {
        return ResponseEntity.ok(ApiResponse.success(responseService.getRecentActions()));
    }

    @PostMapping("/actions/{id}/approve")
    @PreAuthorize("hasRole('ADMIN')")
    @Operation(summary = "Approve and execute a pending response action (Admin required)")
    public ResponseEntity<ApiResponse<ResponseActionDto>> approveAction(@PathVariable Long id, Authentication auth) {
        ResponseActionDto approved = responseService.approveAction(id, auth.getName());
        return ResponseEntity.ok(ApiResponse.success("Action approved and triggered", approved));
    }

    @PostMapping("/actions/{id}/reject")
    @PreAuthorize("hasRole('ADMIN')")
    @Operation(summary = "Reject a pending response action (Admin required)")
    public ResponseEntity<ApiResponse<ResponseActionDto>> rejectAction(@PathVariable Long id, @RequestParam(required = false) String reason, Authentication auth) {
        ResponseActionDto rejected = responseService.rejectAction(id, auth.getName(), reason);
        return ResponseEntity.ok(ApiResponse.success("Action rejected", rejected));
    }

    @PostMapping("/actions/{id}/execute")
    @PreAuthorize("hasRole('ADMIN')")
    @Operation(summary = "Directly execute an approved response action")
    public ResponseEntity<ApiResponse<ResponseExecutionDto>> executeAction(@PathVariable Long id) {
        ResponseExecutionDto exec = responseService.executeAction(id);
        return ResponseEntity.ok(ApiResponse.success("Action execution complete", exec));
    }

    @PostMapping("/actions/{id}/rollback")
    @PreAuthorize("hasRole('ADMIN')")
    @Operation(summary = "Rollback a previously completed response action")
    public ResponseEntity<ApiResponse<ResponseActionDto>> rollbackAction(@PathVariable Long id, Authentication auth) {
        ResponseActionDto rollback = responseService.rollbackAction(id, auth.getName());
        return ResponseEntity.ok(ApiResponse.success("Rollback initiated and executed", rollback));
    }

    @GetMapping("/executions")
    @Operation(summary = "List execution logs and verification telemetry")
    public ResponseEntity<ApiResponse<List<ResponseExecutionDto>>> getExecutions() {
        return ResponseEntity.ok(ApiResponse.success(responseService.getAllExecutions()));
    }
}
