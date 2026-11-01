package com.blueops.audit;

import com.blueops.common.dto.ApiResponse;
import com.blueops.common.dto.PagedResponse;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/v1/audit")
@Tag(name = "Audit Logs", description = "System and administrative compliance audit trail")
public class AuditController {

    private final AuditService auditService;

    public AuditController(AuditService auditService) {
        this.auditService = auditService;
    }

    @GetMapping("/logs")
    @PreAuthorize("hasAnyRole('ADMIN', 'ANALYST')")
    @Operation(summary = "Query paginated audit logs")
    public ResponseEntity<ApiResponse<PagedResponse<AuditLog>>> getLogs(
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "20") int size) {
        Page<AuditLog> paged = auditService.getLogs(PageRequest.of(page, size));
        PagedResponse<AuditLog> response = new PagedResponse<>(
                paged.getContent(), paged.getNumber(), paged.getSize(),
                paged.getTotalElements(), paged.getTotalPages(), paged.isLast()
        );
        return ResponseEntity.ok(ApiResponse.success(response));
    }

    @GetMapping("/logs/{id}")
    @PreAuthorize("hasAnyRole('ADMIN', 'ANALYST')")
    @Operation(summary = "Get specific audit log entry")
    public ResponseEntity<ApiResponse<AuditLog>> getLogById(@PathVariable Long id) {
        return ResponseEntity.ok(ApiResponse.success(auditService.getLogById(id)));
    }
}
