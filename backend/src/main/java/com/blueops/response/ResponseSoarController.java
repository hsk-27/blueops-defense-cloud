package com.blueops.response;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;

/**
 * Controlled SOAR Response & Policy Governance Controller (M6.12)
 * Exposes policy-governed endpoints for action catalog inspection, target authorization,
 * proposal creation, approval, simulation, execution, and verification.
 */
@RestController
@RequestMapping("/api/v1/response/soar")
@Tag(name = "Controlled SOAR Response", description = "Endpoints for policy-governed response orchestration, proposal lifecycles, and verification")
public class ResponseSoarController {

    private final ResponseSoarOrchestrator orchestrator;

    public ResponseSoarController(ResponseSoarOrchestrator orchestrator) {
        this.orchestrator = orchestrator;
    }

    @GetMapping("/catalog")
    @PreAuthorize("hasAnyRole('ADMIN', 'ANALYST', 'VIEWER')")
    @Operation(summary = "List supported response actions from the response catalog")
    public ResponseEntity<List<ResponseActionCatalogDto>> getActionCatalog() {
        return ResponseEntity.ok(orchestrator.getActionCatalog());
    }

    @GetMapping("/targets")
    @PreAuthorize("hasAnyRole('ADMIN', 'ANALYST', 'VIEWER')")
    @Operation(summary = "List registered and authorized response targets")
    public ResponseEntity<List<ResponseTargetDto>> getAuthorizedTargets() {
        return ResponseEntity.ok(orchestrator.getAuthorizedTargets());
    }

    @PostMapping("/policy-preview")
    @PreAuthorize("hasAnyRole('ADMIN', 'ANALYST')")
    @Operation(summary = "Pre-flight evaluate policy constraints for a proposed response action")
    public ResponseEntity<PolicyEvaluationResultDto> previewPolicy(
            @RequestBody CreateProposalRequestDto request,
            Authentication authentication) {
        String actor = authentication != null ? authentication.getName() : "analyst";
        return ResponseEntity.ok(orchestrator.evaluatePolicyPreview(request, actor));
    }

    @PostMapping("/proposals")
    @PreAuthorize("hasAnyRole('ADMIN', 'ANALYST')")
    @Operation(summary = "Create and register a new response proposal")
    public ResponseEntity<ResponseProposalDto> createProposal(
            @RequestBody CreateProposalRequestDto request,
            Authentication authentication) {
        String actor = authentication != null ? authentication.getName() : "analyst";
        ResponseProposalDto proposal = orchestrator.createProposal(request, actor);
        return ResponseEntity.status(HttpStatus.CREATED).body(proposal);
    }

    @GetMapping("/proposals")
    @PreAuthorize("hasAnyRole('ADMIN', 'ANALYST', 'VIEWER')")
    @Operation(summary = "List response proposals with optional status filtering and pagination")
    public ResponseEntity<Page<ResponseProposalDto>> getProposals(
            @RequestParam(required = false) ProposalStatus status,
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "20") int size) {
        PageRequest pageRequest = PageRequest.of(page, size);
        if (status != null) {
            return ResponseEntity.ok(orchestrator.getProposalsByStatus(status, pageRequest));
        }
        return ResponseEntity.ok(orchestrator.getAllProposals(pageRequest));
    }

    @GetMapping("/proposals/{id}")
    @PreAuthorize("hasAnyRole('ADMIN', 'ANALYST', 'VIEWER')")
    @Operation(summary = "Get response proposal details including policy outcome and verification")
    public ResponseEntity<ResponseProposalDto> getProposalById(@PathVariable Long id) {
        return ResponseEntity.ok(orchestrator.getProposalById(id));
    }

    @GetMapping("/incidents/{incidentId}/proposals")
    @PreAuthorize("hasAnyRole('ADMIN', 'ANALYST', 'VIEWER')")
    @Operation(summary = "Get all response proposals associated with an incident")
    public ResponseEntity<List<ResponseProposalDto>> getProposalsByIncident(@PathVariable Long incidentId) {
        return ResponseEntity.ok(orchestrator.getProposalsByIncident(incidentId));
    }

    @PostMapping("/proposals/{id}/approve")
    @PreAuthorize("hasRole('ADMIN')")
    @Operation(summary = "Approve a pending response proposal (enforcing Separation of Duties)")
    public ResponseEntity<ResponseProposalDto> approveProposal(
            @PathVariable Long id,
            @RequestBody(required = false) ApproveProposalRequestDto request,
            Authentication authentication) {
        String approver = authentication != null ? authentication.getName() : "lead-analyst";
        return ResponseEntity.ok(orchestrator.approveProposal(id, request, approver));
    }

    @PostMapping("/proposals/{id}/deny")
    @PreAuthorize("hasRole('ADMIN')")
    @Operation(summary = "Deny a pending response proposal with reason")
    public ResponseEntity<ResponseProposalDto> denyProposal(
            @PathVariable Long id,
            @RequestBody(required = false) Map<String, String> body,
            Authentication authentication) {
        String denier = authentication != null ? authentication.getName() : "lead-analyst";
        String reason = body != null ? body.get("reason") : "Denied by analyst";
        return ResponseEntity.ok(orchestrator.denyProposal(id, reason, denier));
    }

    @PostMapping("/proposals/{id}/cancel")
    @PreAuthorize("hasAnyRole('ADMIN', 'ANALYST')")
    @Operation(summary = "Cancel an active or pending response proposal")
    public ResponseEntity<ResponseProposalDto> cancelProposal(
            @PathVariable Long id,
            @RequestBody(required = false) Map<String, String> body,
            Authentication authentication) {
        String actor = authentication != null ? authentication.getName() : "analyst";
        String reason = body != null ? body.get("reason") : "Cancelled by operator";
        return ResponseEntity.ok(orchestrator.cancelProposal(id, reason, actor));
    }

    @PostMapping("/proposals/{id}/execute")
    @PreAuthorize("hasRole('ADMIN')")
    @Operation(summary = "Dispatch execution for an approved proposal and trigger independent verification")
    public ResponseEntity<ResponseProposalDto> executeProposal(
            @PathVariable Long id,
            Authentication authentication) {
        String actor = authentication != null ? authentication.getName() : "analyst";
        return ResponseEntity.ok(orchestrator.executeProposal(id, actor));
    }

    @GetMapping("/proposals/{id}/verification")
    @PreAuthorize("hasAnyRole('ADMIN', 'ANALYST', 'VIEWER')")
    @Operation(summary = "Retrieve independent verification outcome and evidence for an executed proposal")
    public ResponseEntity<ResponseVerificationDto> getVerification(@PathVariable Long id) {
        return orchestrator.getLatestVerification(id)
                .map(ResponseEntity::ok)
                .orElse(ResponseEntity.notFound().build());
    }
}
