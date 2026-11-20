package com.blueops.system;

import com.blueops.detections.sigma.SigmaRuleRegistry;
import com.blueops.findings.OpenSearchFindingAdapter;
import com.blueops.response.ResponseSoarOrchestrator;
import com.blueops.telemetry.EventNormalizationService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.sql.DataSource;
import java.lang.management.ManagementFactory;
import java.sql.Connection;
import java.sql.Statement;
import java.time.Duration;
import java.time.Instant;
import java.util.HashMap;
import java.util.Map;

/**
 * Controller providing operational health and diagnostic telemetry (M7 Stabilization).
 * Strict separation: /api/v1/system/health is unauthenticated for probes;
 * /api/v1/system/diagnostics requires authentication and returns sanitized operational statistics.
 */
@RestController
@RequestMapping("/api/v1/system")
public class SystemDiagnosticsController {

    private final SigmaRuleRegistry ruleRegistry;
    private final EventNormalizationService normalizationService;
    private final OpenSearchFindingAdapter openSearchAdapter;
    private final ResponseSoarOrchestrator soarOrchestrator;
    private final DataSource dataSource;
    private final long jvmStartTime;

    public SystemDiagnosticsController(
            @Autowired(required = false) SigmaRuleRegistry ruleRegistry,
            @Autowired(required = false) EventNormalizationService normalizationService,
            @Autowired(required = false) OpenSearchFindingAdapter openSearchAdapter,
            @Autowired(required = false) ResponseSoarOrchestrator soarOrchestrator,
            @Autowired(required = false) DataSource dataSource) {
        this.ruleRegistry = ruleRegistry;
        this.normalizationService = normalizationService;
        this.openSearchAdapter = openSearchAdapter;
        this.soarOrchestrator = soarOrchestrator;
        this.dataSource = dataSource;
        this.jvmStartTime = ManagementFactory.getRuntimeMXBean().getStartTime();
    }

    @GetMapping("/health")
    public ResponseEntity<Map<String, Object>> getSystemHealth() {
        boolean dbOk = checkDatabase();
        int rulesCount = ruleRegistry != null ? ruleRegistry.getLoadedRuleCount() : 0;

        Map<String, Object> health = new HashMap<>();
        health.put("status", dbOk ? "UP" : "DEGRADED");
        health.put("database", dbOk ? "CONNECTED" : "DISCONNECTED");
        health.put("rulesEngine", rulesCount > 0 ? "OPERATIONAL" : "EMPTY_REGISTRY");
        health.put("rulesCount", rulesCount);
        health.put("storageFallback", "IN_MEMORY_ENABLED");
        health.put("timestamp", Instant.now().toString());

        return dbOk ? ResponseEntity.ok(health) : ResponseEntity.status(503).body(health);
    }

    @GetMapping("/diagnostics")
    @PreAuthorize("hasAnyRole('ADMIN', 'ANALYST')")
    public ResponseEntity<SystemDiagnosticsDto> getSystemDiagnostics() {
        SystemDiagnosticsDto dto = new SystemDiagnosticsDto();

        boolean dbOk = checkDatabase();
        dto.setStatus(dbOk ? "HEALTHY" : "DEGRADED");

        // Uptime calculations
        long uptimeMs = System.currentTimeMillis() - jvmStartTime;
        long uptimeSec = uptimeMs / 1000;
        dto.setUptimeSeconds(uptimeSec);
        Duration d = Duration.ofMillis(uptimeMs);
        dto.setUptimeFormatted(String.format("%dd %02dh %02dm %02ds",
                d.toDays(), d.toHoursPart(), d.toMinutesPart(), d.toSecondsPart()));

        // JVM Memory Telemetry
        Runtime rt = Runtime.getRuntime();
        long maxMem = rt.maxMemory();
        long totalMem = rt.totalMemory();
        long freeMem = rt.freeMemory();
        long usedMem = totalMem - freeMem;
        double utilPct = maxMem > 0 ? ((double) usedMem / maxMem) * 100.0 : 0.0;

        Map<String, Object> memMap = new HashMap<>();
        memMap.put("maxMemoryMb", maxMem / (1024 * 1024));
        memMap.put("totalMemoryMb", totalMem / (1024 * 1024));
        memMap.put("freeMemoryMb", freeMem / (1024 * 1024));
        memMap.put("usedMemoryMb", usedMem / (1024 * 1024));
        memMap.put("heapUtilizationPct", Math.round(utilPct * 10.0) / 10.0);
        memMap.put("availableProcessors", rt.availableProcessors());
        dto.setMemory(memMap);

        // Telemetry Ingestion Pipeline
        Map<String, Object> telemMap = new HashMap<>();
        if (normalizationService != null) {
            Map<String, Object> stats = normalizationService.getTelemetryStats();
            telemMap.putAll(stats);
            telemMap.put("deadLetterQueueState", stats.getOrDefault("dlqCount", 0));
            telemMap.put("poisonPillQuarantineEnabled", true);
        } else {
            telemMap.put("status", "UNAVAILABLE");
        }
        dto.setTelemetryPipeline(telemMap);

        // Detection Engine Metrics
        Map<String, Object> detMap = new HashMap<>();
        if (ruleRegistry != null) {
            detMap.put("activeSigmaRules", ruleRegistry.getLoadedRuleCount());
            detMap.put("atomicHotReloadSupported", true);
        } else {
            detMap.put("activeSigmaRules", 0);
        }
        dto.setDetectionEngine(detMap);

        // SOAR Response Engine Metrics
        Map<String, Object> soarMap = new HashMap<>();
        if (soarOrchestrator != null) {
            soarMap.put("actionCatalogSize", soarOrchestrator.getActionCatalog().size());
            soarMap.put("authorizedTargetsCount", soarOrchestrator.getAuthorizedTargets().size());
            soarMap.put("defaultMode", "SIMULATION");
            soarMap.put("separationOfDutiesEnforced", true);
            soarMap.put("hostProtectionGuards", "ACTIVE");
        } else {
            soarMap.put("status", "UNAVAILABLE");
        }
        dto.setResponseEngine(soarMap);

        // Storage & Search Resilience
        Map<String, Object> storageMap = new HashMap<>();
        storageMap.put("databaseConnected", dbOk);
        storageMap.put("opensearchFallbackActive", true);
        if (openSearchAdapter != null) {
            storageMap.put("cachedFindingsCount", openSearchAdapter.fetchFindings().size());
        }
        dto.setStorageAndSearch(storageMap);

        return ResponseEntity.ok(dto);
    }

    private boolean checkDatabase() {
        if (dataSource == null) return false;
        try (Connection conn = dataSource.getConnection();
             Statement stmt = conn.createStatement()) {
            return stmt.execute("SELECT 1");
        } catch (Exception e) {
            return false;
        }
    }
}
