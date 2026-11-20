package com.blueops.system;

import com.blueops.detections.sigma.SigmaRuleRegistry;
import com.blueops.telemetry.EventNormalizationService;
import org.springframework.boot.actuate.health.Health;
import org.springframework.boot.actuate.health.HealthIndicator;
import org.springframework.stereotype.Component;

import javax.sql.DataSource;
import java.sql.Connection;
import java.sql.Statement;
import java.util.Map;

/**
 * Spring Boot Actuator Custom Health Indicator for BlueOps SIEM/SOAR platform.
 * Probes database connectivity, Sigma detection rule registry, and telemetry buffer.
 */
@Component("blueopsHealth")
public class BlueOpsHealthIndicator implements HealthIndicator {

    private final DataSource dataSource;
    private final SigmaRuleRegistry ruleRegistry;
    private final EventNormalizationService normalizationService;

    public BlueOpsHealthIndicator(
            DataSource dataSource,
            SigmaRuleRegistry ruleRegistry,
            EventNormalizationService normalizationService) {
        this.dataSource = dataSource;
        this.ruleRegistry = ruleRegistry;
        this.normalizationService = normalizationService;
    }

    @Override
    public Health health() {
        boolean dbOk = checkDatabase();
        int sigmaRules = ruleRegistry != null ? ruleRegistry.getLoadedRuleCount() : 0;
        Map<String, Object> stats = normalizationService != null ? normalizationService.getTelemetryStats() : Map.of();

        Health.Builder builder = dbOk ? Health.up() : Health.down();
        builder.withDetail("database", dbOk ? "CONNECTED" : "DISCONNECTED")
               .withDetail("sigmaRulesLoaded", sigmaRules)
               .withDetail("telemetryBuffered", stats.getOrDefault("bufferedCount", 0))
               .withDetail("dlqDepth", stats.getOrDefault("dlqCount", 0))
               .withDetail("opensearchFallbackActive", true)
               .withDetail("platformStatus", dbOk ? "OPERATIONAL" : "DEGRADED_DATABASE_DOWN");

        return builder.build();
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
