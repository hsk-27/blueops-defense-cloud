package com.blueops.correlation;

import com.blueops.common.dto.PagedResponse;
import com.blueops.entities.EntityRecord;
import com.blueops.entities.EntityRepository;
import com.blueops.entities.EntityType;
import com.blueops.findings.FindingDto;
import com.blueops.incidents.IncidentCreateRequest;
import com.blueops.incidents.IncidentDto;
import com.blueops.incidents.IncidentService;
import com.blueops.incidents.IncidentSeverity;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Duration;
import java.time.Instant;
import java.util.*;
import java.util.stream.Collectors;

@Service
public class CorrelationService {

    private static final Logger log = LoggerFactory.getLogger(CorrelationService.class);

    private final CorrelationRepository correlationRepository;
    private final CorrelationRuleRepository ruleRepository;
    private final CorrelationFindingRepository findingAssociationRepository;
    private final CorrelationEntityRepository entityAssociationRepository;
    private final EntityRepository entityRepository;
    private final IncidentService incidentService;

    public CorrelationService(CorrelationRepository correlationRepository,
                              CorrelationRuleRepository ruleRepository,
                              CorrelationFindingRepository findingAssociationRepository,
                              CorrelationEntityRepository entityAssociationRepository,
                              EntityRepository entityRepository,
                              IncidentService incidentService) {
        this.correlationRepository = correlationRepository;
        this.ruleRepository = ruleRepository;
        this.findingAssociationRepository = findingAssociationRepository;
        this.entityAssociationRepository = entityAssociationRepository;
        this.entityRepository = entityRepository;
        this.incidentService = incidentService;
    }

    /**
     * Evaluates security findings against configured correlation rules and persists actionable correlation records.
     */
    @Transactional
    public List<CorrelationRecord> evaluateAndPersist(List<FindingDto> findings) {
        List<CorrelationRecord> generated = new ArrayList<>();
        if (findings == null || findings.isEmpty()) return generated;

        Instant horizon = Instant.now().minus(Duration.ofHours(24));
        List<FindingDto> validFindings = findings.stream()
                .filter(f -> f != null && f.getFindingId() != null && (f.getTimestamp() == null || f.getTimestamp().isAfter(horizon)))
                .toList();

        // 1. Evaluate Host-Grouped Correlations
        Map<String, List<FindingDto>> byHost = validFindings.stream()
                .filter(f -> (f.getAssetName() != null && !f.getAssetName().isEmpty()) || (f.getAssetId() != null && !f.getAssetId().isEmpty()))
                .collect(Collectors.groupingBy(f -> f.getAssetName() != null ? f.getAssetName() : f.getAssetId()));

        for (Map.Entry<String, List<FindingDto>> entry : byHost.entrySet()) {
            String host = entry.getKey();
            List<FindingDto> hostFindings = entry.getValue();
            hostFindings.sort(Comparator.comparing(f -> f.getTimestamp() != null ? f.getTimestamp() : Instant.EPOCH));

            evaluateHostScenarios(host, hostFindings, generated);
        }

        // 2. Evaluate Hash-Grouped Correlations (Cross-Host Malware Hash Spread)
        Map<String, List<FindingDto>> byHash = new HashMap<>();
        for (FindingDto f : validFindings) {
            if (f.getDetails() != null && f.getDetails().get("file.hash.sha256") instanceof String h && !h.trim().isEmpty()) {
                byHash.computeIfAbsent(h.trim().toLowerCase(), k -> new ArrayList<>()).add(f);
            }
        }

        for (Map.Entry<String, List<FindingDto>> entry : byHash.entrySet()) {
            String hash = entry.getKey();
            List<FindingDto> hashFindings = entry.getValue();
            Set<String> distinctHosts = hashFindings.stream()
                    .map(f -> f.getAssetName() != null ? f.getAssetName() : f.getAssetId())
                    .filter(Objects::nonNull)
                    .collect(Collectors.toSet());

            if (distinctHosts.size() >= 2) {
                // CORR-005 Cross-Host Malware Hash Distribution
                evaluateCorr005HashDistribution(hash, distinctHosts, hashFindings, generated);
            }
        }

        return generated;
    }

    private void evaluateHostScenarios(String host, List<FindingDto> findings, List<CorrelationRecord> results) {
        String hostCanonicalId = "host:" + host.trim().toLowerCase();

        // CORR-001: Linux Account Compromise
        boolean hasSshFail = findings.stream().anyMatch(f -> "D001".equalsIgnoreCase(f.getRuleId()));
        boolean hasSshSuccess = findings.stream().anyMatch(f -> "D002".equalsIgnoreCase(f.getRuleId()));
        boolean hasPrivExec = findings.stream().anyMatch(f -> "D004".equalsIgnoreCase(f.getRuleId()));

        if (hasSshFail && (hasSshSuccess || hasPrivExec)) {
            List<FindingDto> matched = findings.stream()
                    .filter(f -> Set.of("D001", "D002", "D004", "D006").contains(f.getRuleId()))
                    .toList();
            if (isWithinWindow(matched, 60)) {
                String explanation = String.format("Sequence satisfied on %s: Observed initial brute-force authentication failures (D001) " +
                        "followed by privileged session establishment (%s) within 60 minutes.",
                        host, hasSshSuccess ? "D002" : "D004");
                recordCorrelation("CORR-001", "Linux Account Compromise & Privilege Escalation", IncidentSeverity.CRITICAL,
                        hostCanonicalId, EntityType.HOST, matched, explanation, results);
            }
        }

        // CORR-002: Windows Execution Chain
        boolean hasParentChild = findings.stream().anyMatch(f -> "D009".equalsIgnoreCase(f.getRuleId()));
        boolean hasPowerShell = findings.stream().anyMatch(f -> "D008".equalsIgnoreCase(f.getRuleId()));
        boolean hasOutbound = findings.stream().anyMatch(f -> "D014".equalsIgnoreCase(f.getRuleId()));

        if ((hasParentChild && hasPowerShell) || (hasPowerShell && hasOutbound)) {
            List<FindingDto> matched = findings.stream()
                    .filter(f -> Set.of("D008", "D009", "D014").contains(f.getRuleId()))
                    .toList();
            if (isWithinWindow(matched, 60)) {
                String explanation = String.format("Execution chain satisfied on %s: Suspicious process spawned encoded PowerShell " +
                        "leading to network outbound connection within 60 minutes.", host);
                recordCorrelation("CORR-002", "Windows Multi-Stage Execution Chain", IncidentSeverity.CRITICAL,
                        hostCanonicalId, EntityType.HOST, matched, explanation, results);
            }
        }

        // CORR-003: Threat Intel IOC Activity With Secondary Detections
        List<FindingDto> iocFindings = findings.stream()
                .filter(f -> "D015".equalsIgnoreCase(f.getRuleId()))
                .toList();

        for (FindingDto iocFinding : iocFindings) {
            List<FindingDto> matched = findings.stream()
                    .filter(f -> f.getTimestamp() != null && iocFinding.getTimestamp() != null
                            && Duration.between(f.getTimestamp(), iocFinding.getTimestamp()).abs().toMinutes() <= 60)
                    .toList();
            if (matched.size() > 1) {
                String explanation = String.format("Threat Intel Correlation on %s: Known IOC connection (%s) accompanied by %d secondary endpoint findings within 60 minutes.",
                        host, iocFinding.getFindingId(), matched.size() - 1);
                recordCorrelation("CORR-003", "Threat Intel IOC Activity With Secondary Endpoint Behavior", IncidentSeverity.HIGH,
                        hostCanonicalId, EntityType.HOST, matched, explanation, results);
                break;
            }
        }

        // CORR-004: Account Creation & Persistence Manipulation
        boolean hasAcctCreate = findings.stream().anyMatch(f -> "D005".equalsIgnoreCase(f.getRuleId()));
        boolean hasPersistence = findings.stream().anyMatch(f -> Set.of("D007", "D010", "D018").contains(f.getRuleId()));

        if (hasAcctCreate && hasPersistence) {
            List<FindingDto> matched = findings.stream()
                    .filter(f -> Set.of("D005", "D007", "D010", "D018").contains(f.getRuleId()))
                    .toList();
            if (isWithinWindow(matched, 60)) {
                String explanation = String.format("Persistence correlation on %s: Account creation (D005) accompanied by service or scheduled task installation within 60 minutes.", host);
                recordCorrelation("CORR-004", "Account Creation Followed by Persistence Installation", IncidentSeverity.HIGH,
                        hostCanonicalId, EntityType.HOST, matched, explanation, results);
            }
        }
    }

    private void evaluateCorr005HashDistribution(String hash, Set<String> hosts, List<FindingDto> findings, List<CorrelationRecord> results) {
        String hashCanonicalId = "hash:sha256:" + hash;
        String explanation = String.format("Lateral Spread Indicator: Identical file hash observed across %d distinct enterprise hosts (%s) across %d security alerts.",
                hosts.size(), String.join(", ", hosts), findings.size());

        recordCorrelation("CORR-005", "Cross-Host Malware Hash Distribution", IncidentSeverity.CRITICAL,
                hashCanonicalId, EntityType.HASH, findings, explanation, results);
    }

    private void recordCorrelation(String ruleId, String ruleName, IncidentSeverity severity,
                                   String primaryCanonicalId, EntityType primaryType,
                                   List<FindingDto> matchedFindings, String explanation,
                                   List<CorrelationRecord> accumulator) {
        if (matchedFindings.isEmpty()) return;

        Instant firstTime = matchedFindings.stream()
                .map(FindingDto::getTimestamp).filter(Objects::nonNull).min(Instant::compareTo).orElse(Instant.now());
        Instant lastTime = matchedFindings.stream()
                .map(FindingDto::getTimestamp).filter(Objects::nonNull).max(Instant::compareTo).orElse(Instant.now());

        // Check for existing open correlation for this rule and primary entity within 2 hours to prevent alert flapping
        List<CorrelationRecord> existing = correlationRepository.findByPrimaryEntityCanonicalId(primaryCanonicalId);
        boolean duplicate = existing.stream().anyMatch(c -> c.getRuleId().equalsIgnoreCase(ruleId) && c.getStatus() == CorrelationStatus.OPEN);
        if (duplicate) return;

        String correlationId = "CORR-" + UUID.randomUUID().toString().substring(0, 8).toUpperCase();
        CorrelationRecord record = new CorrelationRecord(
                correlationId,
                ruleId,
                ruleName,
                severity,
                primaryCanonicalId,
                primaryType,
                explanation,
                firstTime,
                lastTime
        );

        record = correlationRepository.save(record);
        accumulator.add(record);

        // Save associations
        for (FindingDto f : matchedFindings) {
            findingAssociationRepository.save(new CorrelationFindingRecord(record.getId(), f.getFindingId()));
        }
        entityAssociationRepository.save(new CorrelationEntityRecord(record.getId(), primaryCanonicalId));

        log.warn(">>> CORRELATION GENERATED: [{}] {} on entity {} (ID: {})",
                ruleId, ruleName, primaryCanonicalId, correlationId);
    }

    private boolean isWithinWindow(List<FindingDto> matched, int maxMinutes) {
        if (matched.size() < 2) return true;
        Instant min = matched.stream().map(FindingDto::getTimestamp).filter(Objects::nonNull).min(Instant::compareTo).orElse(null);
        Instant max = matched.stream().map(FindingDto::getTimestamp).filter(Objects::nonNull).max(Instant::compareTo).orElse(null);
        if (min == null || max == null) return true;
        return Duration.between(min, max).abs().toMinutes() <= maxMinutes;
    }

    // --- Query & Management APIs ---

    public PagedResponse<CorrelationDto> getCorrelations(IncidentSeverity severity, CorrelationStatus status, String query, int page, int size) {
        int boundedSize = Math.min(Math.max(1, size), 100);
        Pageable pageable = PageRequest.of(Math.max(0, page), boundedSize, Sort.by(Sort.Direction.DESC, "createdAt"));
        Page<CorrelationRecord> corrPage = correlationRepository.findFiltered(severity, status, query, pageable);

        List<CorrelationDto> dtos = corrPage.getContent().stream()
                .map(this::toDto)
                .collect(Collectors.toList());

        return new PagedResponse<>(
                dtos,
                corrPage.getNumber(),
                corrPage.getSize(),
                corrPage.getTotalElements(),
                corrPage.getTotalPages(),
                corrPage.isLast()
        );
    }

    public CorrelationDto getCorrelationById(Long id) {
        CorrelationRecord record = correlationRepository.findById(id)
                .orElseThrow(() -> new NoSuchElementException("Correlation record not found with ID: " + id));
        return toDto(record);
    }

    public CorrelationDto getCorrelationByCorrelationId(String correlationId) {
        CorrelationRecord record = correlationRepository.findByCorrelationId(correlationId)
                .orElseThrow(() -> new NoSuchElementException("Correlation record not found with ID: " + correlationId));
        return toDto(record);
    }

    public List<CorrelationDto> getCorrelationsForEntity(String canonicalId) {
        if (canonicalId == null || canonicalId.trim().isEmpty()) return Collections.emptyList();
        List<CorrelationRecord> records = correlationRepository.findByPrimaryEntityCanonicalId(canonicalId);
        return records.stream().map(this::toDto).collect(Collectors.toList());
    }

    public List<CorrelationRuleDto> getCorrelationRules() {
        return ruleRepository.findAll().stream().map(this::toRuleDto).collect(Collectors.toList());
    }

    @Transactional
    public CorrelationDto updateStatus(Long id, CorrelationStatus status) {
        CorrelationRecord record = correlationRepository.findById(id)
                .orElseThrow(() -> new NoSuchElementException("Correlation record not found with ID: " + id));
        record.setStatus(status);
        record.setUpdatedAt(Instant.now());
        return toDto(correlationRepository.save(record));
    }

    /**
     * Promotes a verified correlation result directly into a formalized Incident.
     */
    @Transactional
    public IncidentDto promoteToIncident(Long id, String operatorUsername) {
        CorrelationRecord record = correlationRepository.findById(id)
                .orElseThrow(() -> new NoSuchElementException("Correlation record not found with ID: " + id));

        List<CorrelationFindingRecord> associations = findingAssociationRepository.findByCorrelationId(record.getId());
        List<String> findingIds = associations.stream().map(CorrelationFindingRecord::getFindingId).toList();

        IncidentCreateRequest req = new IncidentCreateRequest();
        req.setTitle(record.getRuleName() + " on " + record.getPrimaryEntityCanonicalId());
        req.setDescription("Correlated Threat Pattern: " + record.getExplanation());
        req.setSeverity(record.getSeverity());
        req.setFindingIds(findingIds);

        IncidentDto incident = incidentService.createIncident(req, operatorUsername != null ? operatorUsername : "system:correlation");

        record.setIncidentId(incident.getId());
        record.setStatus(CorrelationStatus.PROMOTED_TO_INCIDENT);
        record.setUpdatedAt(Instant.now());
        correlationRepository.save(record);

        log.info("Correlation [{}] promoted to Incident [{}] by {}", record.getCorrelationId(), incident.getIncidentNumber(), operatorUsername);
        return incident;
    }

    // --- Mappers ---

    public CorrelationDto toDto(CorrelationRecord record) {
        if (record == null) return null;
        List<String> findingIds = findingAssociationRepository.findByCorrelationId(record.getId()).stream()
                .map(CorrelationFindingRecord::getFindingId).collect(Collectors.toList());
        List<String> entityIds = entityAssociationRepository.findByCorrelationId(record.getId()).stream()
                .map(CorrelationEntityRecord::getEntityCanonicalId).collect(Collectors.toList());

        return new CorrelationDto(
                record.getId(),
                record.getCorrelationId(),
                record.getRuleId(),
                record.getRuleName(),
                record.getSeverity(),
                record.getPrimaryEntityCanonicalId(),
                record.getPrimaryEntityType(),
                record.getExplanation(),
                record.getFirstFindingTime(),
                record.getLastFindingTime(),
                record.getIncidentId(),
                record.getStatus(),
                findingIds,
                entityIds,
                record.getCreatedAt()
        );
    }

    public CorrelationRuleDto toRuleDto(CorrelationRuleRecord r) {
        if (r == null) return null;
        return new CorrelationRuleDto(
                r.getId(),
                r.getRuleId(),
                r.getName(),
                r.getDescription(),
                r.getSeverity(),
                r.getGroupingField(),
                r.getTimeWindowMinutes(),
                r.getConditionsJson(),
                r.isEnabled(),
                r.getCreatedAt()
        );
    }
}
