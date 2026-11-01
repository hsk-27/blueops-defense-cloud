package com.blueops.assets;

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
import java.util.Map;

@RestController
@RequestMapping("/api/v1/assets")
@Tag(name = "Assets", description = "Monitored host inventory and telemetry status")
public class AssetController {

    private final AssetService assetService;

    public AssetController(AssetService assetService) {
        this.assetService = assetService;
    }

    @GetMapping
    @Operation(summary = "Get list of all monitored assets")
    public ResponseEntity<ApiResponse<List<AssetDto>>> getAllAssets() {
        return ResponseEntity.ok(ApiResponse.success(assetService.getAllAssets()));
    }

    @GetMapping("/{id}")
    @Operation(summary = "Get specific asset by ID")
    public ResponseEntity<ApiResponse<AssetDto>> getAssetById(@PathVariable Long id) {
        return ResponseEntity.ok(ApiResponse.success(assetService.getAssetById(id)));
    }

    @PostMapping
    @PreAuthorize("hasAnyRole('ADMIN', 'ANALYST')")
    @Operation(summary = "Register a new monitored asset")
    public ResponseEntity<ApiResponse<AssetDto>> createAsset(@Valid @RequestBody AssetDto dto, Authentication auth) {
        AssetDto created = assetService.createAsset(dto, auth.getName());
        return ResponseEntity.status(HttpStatus.CREATED).body(ApiResponse.success("Asset created", created));
    }

    @PutMapping("/{id}")
    @PreAuthorize("hasAnyRole('ADMIN', 'ANALYST')")
    @Operation(summary = "Update asset details or operational status")
    public ResponseEntity<ApiResponse<AssetDto>> updateAsset(@PathVariable Long id, @Valid @RequestBody AssetDto dto, Authentication auth) {
        AssetDto updated = assetService.updateAsset(id, dto, auth.getName());
        return ResponseEntity.ok(ApiResponse.success("Asset updated", updated));
    }

    @DeleteMapping("/{id}")
    @PreAuthorize("hasRole('ADMIN')")
    @Operation(summary = "Deregister an asset")
    public ResponseEntity<ApiResponse<Void>> deleteAsset(@PathVariable Long id) {
        assetService.deleteAsset(id);
        return ResponseEntity.ok(ApiResponse.success("Asset deleted", null));
    }

    @GetMapping("/{id}/history")
    @Operation(summary = "Get asset status change history")
    public ResponseEntity<ApiResponse<List<Map<String, Object>>>> getAssetHistory(@PathVariable Long id) {
        return ResponseEntity.ok(ApiResponse.success(assetService.getAssetStatusHistory(id)));
    }
}
