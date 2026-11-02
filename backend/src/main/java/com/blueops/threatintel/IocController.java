package com.blueops.threatintel;

import com.blueops.common.dto.ApiResponse;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/v1/threat-intel")
@Tag(name = "Threat Intelligence", description = "IOC management, confidence scoring, and telemetry matching")
public class IocController {

    private final IocService iocService;

    public IocController(IocService iocService) {
        this.iocService = iocService;
    }

    @GetMapping("/iocs")
    @Operation(summary = "Get all threat intelligence indicators")
    public ResponseEntity<ApiResponse<List<IocDto>>> getAllIocs() {
        return ResponseEntity.ok(ApiResponse.success(iocService.getAllIocs()));
    }

    @GetMapping("/iocs/{id}")
    @Operation(summary = "Get specific IOC details")
    public ResponseEntity<ApiResponse<IocDto>> getIocById(@PathVariable Long id) {
        return ResponseEntity.ok(ApiResponse.success(iocService.getIocById(id)));
    }

    @PostMapping("/iocs")
    @PreAuthorize("hasAnyRole('ADMIN', 'ANALYST')")
    @Operation(summary = "Create a new threat indicator")
    public ResponseEntity<ApiResponse<IocDto>> createIoc(@Valid @RequestBody IocDto dto) {
        IocDto created = iocService.createIoc(dto);
        return ResponseEntity.status(HttpStatus.CREATED).body(ApiResponse.success("IOC created", created));
    }

    @PutMapping("/iocs/{id}")
    @PreAuthorize("hasAnyRole('ADMIN', 'ANALYST')")
    @Operation(summary = "Update an existing threat indicator")
    public ResponseEntity<ApiResponse<IocDto>> updateIoc(@PathVariable Long id, @Valid @RequestBody IocDto dto) {
        IocDto updated = iocService.updateIoc(id, dto);
        return ResponseEntity.ok(ApiResponse.success("IOC updated", updated));
    }

    @DeleteMapping("/iocs/{id}")
    @PreAuthorize("hasRole('ADMIN')")
    @Operation(summary = "Delete or revoke a threat indicator")
    public ResponseEntity<ApiResponse<Void>> deleteIoc(@PathVariable Long id) {
        iocService.deleteIoc(id);
        return ResponseEntity.ok(ApiResponse.success("IOC deleted", null));
    }

    @PostMapping("/import")
    @PreAuthorize("hasAnyRole('ADMIN', 'ANALYST')")
    @Operation(summary = "Bulk import threat indicators from CSV")
    public ResponseEntity<ApiResponse<Map<String, Object>>> importCsv(@RequestBody String csvContent) {
        Map<String, Object> result = iocService.importIocsFromCsv(csvContent);
        return ResponseEntity.ok(ApiResponse.success("CSV import completed", result));
    }

    @GetMapping("/matches")
    @Operation(summary = "Retrieve telemetry events matched against active IOCs")
    public ResponseEntity<ApiResponse<List<IocMatchDto>>> getMatches() {
        return ResponseEntity.ok(ApiResponse.success(iocService.getRecentMatches()));
    }

    @GetMapping("/sources")
    @Operation(summary = "List all distinct threat intelligence provider sources")
    public ResponseEntity<ApiResponse<List<String>>> getSources() {
        return ResponseEntity.ok(ApiResponse.success(iocService.getSources()));
    }
}
