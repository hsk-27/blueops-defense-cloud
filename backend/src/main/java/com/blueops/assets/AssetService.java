package com.blueops.assets;

import com.blueops.audit.AuditService;
import com.blueops.common.exceptions.InvalidActionException;
import com.blueops.common.exceptions.ResourceNotFoundException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

@Service
public class AssetService {

    private final AssetRepository assetRepository;
    private final JdbcTemplate jdbcTemplate;
    private final AuditService auditService;

    @Autowired
    public AssetService(AssetRepository assetRepository, JdbcTemplate jdbcTemplate, @Autowired(required = false) AuditService auditService) {
        this.assetRepository = assetRepository;
        this.jdbcTemplate = jdbcTemplate;
        this.auditService = auditService;
    }

    public AssetService(AssetRepository assetRepository, JdbcTemplate jdbcTemplate) {
        this(assetRepository, jdbcTemplate, null);
    }

    @Transactional(readOnly = true)
    public List<AssetDto> getAllAssets() {
        return assetRepository.findAll().stream()
                .map(AssetDto::new)
                .collect(Collectors.toList());
    }

    @Transactional(readOnly = true)
    public AssetDto getAssetById(Long id) {
        Asset asset = assetRepository.findById(id)
                .orElseThrow(() -> new ResourceNotFoundException("Asset", "id", id));
        return new AssetDto(asset);
    }

    @Transactional(readOnly = true)
    public Asset getAssetEntityById(Long id) {
        return assetRepository.findById(id)
                .orElseThrow(() -> new ResourceNotFoundException("Asset", "id", id));
    }

    @Transactional
    public AssetDto createAsset(AssetDto dto, String actor) {
        if (assetRepository.existsByPersistentId(dto.getPersistentId())) {
            throw new InvalidActionException("Asset with persistent ID already exists: " + dto.getPersistentId());
        }

        Asset asset = new Asset();
        asset.setPersistentId(dto.getPersistentId());
        asset.setHostname(dto.getHostname());
        asset.setIpAddress(dto.getIpAddress());
        asset.setOsName(dto.getOsName());
        asset.setOsVersion(dto.getOsVersion());
        asset.setEnvironment(dto.getEnvironment() != null ? dto.getEnvironment() : "LAB");
        asset.setStatus(dto.getStatus() != null ? dto.getStatus() : AssetStatus.HEALTHY);
        asset.setCriticality(dto.getCriticality() != null ? dto.getCriticality() : "MEDIUM");
        asset.setLastTelemetryAt(Instant.now());

        Asset saved = assetRepository.save(asset);
        recordStatusHistory(saved.getId(), "NONE", saved.getStatus().name(), "Asset onboarding", actor);
        if (auditService != null) {
            auditService.recordEvent(actor, "ASSET_CREATED", "Asset", String.valueOf(saved.getId()), null,
                    "Onboarded asset: " + saved.getHostname() + " (" + saved.getIpAddress() + ")");
        }
        return new AssetDto(saved);
    }

    @Transactional
    public Asset recordTelemetryHeartbeat(String persistentId, String hostname, String ipAddress, String osName) {
        if (persistentId == null || persistentId.trim().isEmpty()) {
            return null;
        }
        Asset asset = assetRepository.findByPersistentId(persistentId)
                .or(() -> assetRepository.findByHostname(hostname))
                .or(() -> assetRepository.findByIpAddress(ipAddress))
                .orElseGet(() -> {
                    Asset newAsset = new Asset();
                    newAsset.setPersistentId(persistentId);
                    newAsset.setHostname(hostname != null && !hostname.isBlank() ? hostname : persistentId);
                    newAsset.setIpAddress(ipAddress != null && !ipAddress.isBlank() ? ipAddress : "0.0.0.0");
                    newAsset.setOsName(osName != null && !osName.isBlank() ? osName : "Linux");
                    newAsset.setOsVersion("Discovered Endpoint");
                    newAsset.setEnvironment("LAB");
                    newAsset.setStatus(AssetStatus.HEALTHY);
                    newAsset.setCriticality("MEDIUM");
                    newAsset.setLastTelemetryAt(Instant.now());
                    Asset saved = assetRepository.save(newAsset);
                    recordStatusHistory(saved.getId(), "NONE", "HEALTHY", "Dynamic discovery via telemetry ingestion", "system:telemetry-collector");
                    return saved;
                });

        asset.setLastTelemetryAt(Instant.now());
        if (hostname != null && !hostname.isBlank() && !asset.getHostname().equals(hostname)) {
            asset.setHostname(hostname);
        }
        if (ipAddress != null && !ipAddress.isBlank() && !"0.0.0.0".equals(ipAddress) && !asset.getIpAddress().equals(ipAddress)) {
            asset.setIpAddress(ipAddress);
        }
        return assetRepository.save(asset);
    }

    @Transactional
    public AssetDto updateAsset(Long id, AssetDto dto, String actor) {
        Asset asset = assetRepository.findById(id)
                .orElseThrow(() -> new ResourceNotFoundException("Asset", "id", id));

        AssetStatus prevStatus = asset.getStatus();
        asset.setHostname(dto.getHostname());
        asset.setIpAddress(dto.getIpAddress());
        asset.setOsName(dto.getOsName());
        asset.setOsVersion(dto.getOsVersion());
        asset.setEnvironment(dto.getEnvironment());
        asset.setCriticality(dto.getCriticality());
        if (dto.getStatus() != null && dto.getStatus() != prevStatus) {
            asset.setStatus(dto.getStatus());
            recordStatusHistory(asset.getId(), prevStatus.name(), dto.getStatus().name(), "Analyst update", actor);
        }
        asset.setUpdatedAt(Instant.now());

        Asset updated = assetRepository.save(asset);
        if (auditService != null) {
            auditService.recordEvent(actor, "ASSET_UPDATED", "Asset", String.valueOf(updated.getId()), null,
                    "Updated asset: " + updated.getHostname() + ", Status: " + updated.getStatus());
        }
        return new AssetDto(updated);
    }

    @Transactional
    public void deleteAsset(Long id) {
        Asset asset = assetRepository.findById(id)
                .orElseThrow(() -> new ResourceNotFoundException("Asset", "id", id));
        if (auditService != null) {
            auditService.recordEvent("admin", "ASSET_DELETED", "Asset", String.valueOf(id), null,
                    "Deleted asset: " + asset.getHostname() + " (" + asset.getIpAddress() + ")");
        }
        assetRepository.deleteById(id);
    }

    @Transactional(readOnly = true)
    public List<Map<String, Object>> getAssetStatusHistory(Long id) {
        return jdbcTemplate.queryForList(
                "SELECT id, asset_id, previous_status, new_status, reason, changed_by, changed_at FROM asset_status_history WHERE asset_id = ? ORDER BY changed_at DESC",
                id
        );
    }

    private void recordStatusHistory(Long assetId, String prev, String next, String reason, String actor) {
        try {
            jdbcTemplate.update(
                    "INSERT INTO asset_status_history (asset_id, previous_status, new_status, reason, changed_by, changed_at) VALUES (?, ?, ?, ?, ?, CURRENT_TIMESTAMP)",
                    assetId, prev, next, reason, actor != null ? actor : "system"
            );
        } catch (Exception ignored) {}
    }
}
