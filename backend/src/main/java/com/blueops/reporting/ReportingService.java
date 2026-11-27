package com.blueops.reporting;

import com.blueops.assets.AssetRepository;
import com.blueops.detections.DetectionRule;
import com.blueops.detections.DetectionRuleRepository;
import com.blueops.detections.sigma.SigmaRuleRegistry;
import com.blueops.incidents.Incident;
import com.blueops.incidents.IncidentRepository;
import com.blueops.incidents.IncidentSeverity;
import com.blueops.response.ResponseActionRepository;
import com.blueops.telemetry.EventNormalizationService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Duration;
import java.util.*;
import java.util.stream.Collectors;

@Service
public class ReportingService {

    private final IncidentRepository incidentRepository;
    private final AssetRepository assetRepository;
    private final DetectionRuleRepository detectionRuleRepository;
    private final ResponseActionRepository responseActionRepository;
    private final JdbcTemplate jdbcTemplate;
    private final SigmaRuleRegistry sigmaRuleRegistry;
    private final EventNormalizationService normalizationService;
    private final boolean opensearchEnabled;
    private final boolean simulationMode;

    public ReportingService(
            IncidentRepository incidentRepository,
            AssetRepository assetRepository,
            DetectionRuleRepository detectionRuleRepository,
            ResponseActionRepository responseActionRepository,
            JdbcTemplate jdbcTemplate) {
        this(incidentRepository, assetRepository, detectionRuleRepository, responseActionRepository,
                jdbcTemplate, null, null, false, true);
    }

    @Autowired
    public ReportingService(
            IncidentRepository incidentRepository,
            AssetRepository assetRepository,
            DetectionRuleRepository detectionRuleRepository,
            ResponseActionRepository responseActionRepository,
            JdbcTemplate jdbcTemplate,
            @Autowired(required = false) SigmaRuleRegistry sigmaRuleRegistry,
            @Autowired(required = false) EventNormalizationService normalizationService,
            @Value("${blueops.opensearch.enabled:false}") boolean opensearchEnabled,
            @Value("${blueops.response-agent.simulation-mode:true}") boolean simulationMode) {
        this.incidentRepository = incidentRepository;
        this.assetRepository = assetRepository;
        this.detectionRuleRepository = detectionRuleRepository;
        this.responseActionRepository = responseActionRepository;
        this.jdbcTemplate = jdbcTemplate;
        this.sigmaRuleRegistry = sigmaRuleRegistry;
        this.normalizationService = normalizationService;
        this.opensearchEnabled = opensearchEnabled;
        this.simulationMode = simulationMode;
    }

    @Transactional(readOnly = true)
    public SocOverviewMetricsDto getSocOverviewMetrics() {
        SocOverviewMetricsDto dto = new SocOverviewMetricsDto();

        dto.setTotalIncidents(incidentRepository.count());
        dto.setActiveIncidents(incidentRepository.countActiveIncidents());
        dto.setCriticalIncidents(incidentRepository.countBySeverity(IncidentSeverity.CRITICAL));
        dto.setHighIncidents(incidentRepository.countBySeverity(IncidentSeverity.HIGH));
        dto.setMediumIncidents(incidentRepository.countBySeverity(IncidentSeverity.MEDIUM));
        dto.setLowIncidents(incidentRepository.countBySeverity(IncidentSeverity.LOW));

        dto.setTotalAssets(assetRepository.count());
        dto.setAssetsWithAlerts(incidentRepository.countAssetsWithActiveIncidents());

        dto.setTotalDetectionRules(detectionRuleRepository.count());
        dto.setActiveDetectionRules(detectionRuleRepository.countByStatus("ACTIVE"));

        // Calculate MTTR honestly from contained incidents; return null when no empirical data exists
        List<Incident> contained = incidentRepository.findByContainedAtIsNotNullAndCreatedAtIsNotNull();

        if (!contained.isEmpty()) {
            double avgMttrSeconds = contained.stream()
                    .mapToLong(i -> Math.max(0L, Duration.between(i.getCreatedAt(), i.getContainedAt()).toSeconds()))
                    .average()
                    .orElse(0.0);
            dto.setMeanTimeToRespondSeconds((double) Math.round(avgMttrSeconds));
        } else {
            dto.setMeanTimeToRespondSeconds(null);
        }

        // Do not fabricate MTTD baseline when no automated detection-latency measurement is recorded
        dto.setMeanTimeToDetectSeconds(null);

        // Truthful subsystem status derived from actual state & configuration
        Map<String, String> health = new LinkedHashMap<>();
        health.put("database", checkDatabaseStatus());
        health.put("opensearch", opensearchEnabled ? "CONFIGURED_EXTERNAL" : "IN_MEMORY_FALLBACK");
        health.put("fluentBit", checkFluentBitStatus());
        health.put("detectionEngine", checkDetectionEngineStatus());
        health.put("responseAgent", simulationMode ? "SIMULATION_MODE" : "CONFIGURED_LIVE");
        dto.setSubsystemHealth(health);

        // MITRE Tactic distribution
        Map<String, Long> tacticCounts = detectionRuleRepository.findAll().stream()
                .collect(Collectors.groupingBy(DetectionRule::getMitreTactic, Collectors.counting()));
        List<Map<String, Object>> tactics = new ArrayList<>();
        tacticCounts.forEach((tactic, count) -> {
            Map<String, Object> m = new HashMap<>();
            m.put("tactic", tactic);
            m.put("count", count);
            tactics.add(m);
        });
        dto.setDetectionTacticDistribution(tactics);

        // Recent Incidents
        List<Map<String, Object>> recentIncs = incidentRepository.findTop5ByOrderByCreatedAtDesc().stream()
                .map(i -> {
                    Map<String, Object> m = new HashMap<>();
                    m.put("id", i.getId());
                    m.put("incidentNumber", i.getIncidentNumber());
                    m.put("title", i.getTitle());
                    m.put("severity", i.getSeverity().name());
                    m.put("status", i.getStatus().name());
                    m.put("createdAt", i.getCreatedAt());
                    return m;
                })
                .collect(Collectors.toList());
        dto.setRecentIncidents(recentIncs);

        return dto;
    }

    @Transactional(readOnly = true)
    public Map<String, Object> getAttackCoverage() {
        List<DetectionRule> rules = detectionRuleRepository.findAll();
        Set<String> coveredTechniques = rules.stream()
                .map(DetectionRule::getMitreTechniqueId)
                .collect(Collectors.toSet());

        Map<String, Object> coverage = new HashMap<>();
        coverage.put("totalRules", rules.size());
        coverage.put("distinctTechniquesCovered", coveredTechniques.size());
        coverage.put("coveredTechniques", coveredTechniques);
        coverage.put("tacticBreakdown", rules.stream().collect(Collectors.groupingBy(DetectionRule::getMitreTactic, Collectors.counting())));
        return coverage;
    }

    private String checkDatabaseStatus() {
        try {
            jdbcTemplate.queryForObject("SELECT 1", Integer.class);
            return "CONNECTED";
        } catch (Exception ex) {
            return "DISCONNECTED";
        }
    }

    private String checkFluentBitStatus() {
        if (normalizationService == null) {
            return "UNAVAILABLE";
        }
        boolean seenFluentBit = normalizationService.getRecentEvents(100).stream()
                .anyMatch(e -> e.getBlueops() != null && "fluent-bit".equalsIgnoreCase(e.getBlueops().getCollector()));
        return seenFluentBit ? "RECEIVING" : "STANDBY_NO_COLLECTOR_EVENTS";
    }

    private String checkDetectionEngineStatus() {
        if (sigmaRuleRegistry != null && sigmaRuleRegistry.getLoadedRuleCount() > 0) {
            return "OPERATIONAL";
        }
        return detectionRuleRepository.count() > 0 ? "DB_RULES_ONLY" : "EMPTY_REGISTRY";
    }
}
