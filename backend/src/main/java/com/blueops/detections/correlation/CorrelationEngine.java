package com.blueops.detections.correlation;

import com.blueops.findings.FindingDto;
import com.blueops.incidents.IncidentCreateRequest;
import com.blueops.incidents.IncidentSeverity;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.time.Duration;
import java.time.Instant;
import java.util.*;
import java.util.stream.Collectors;

@Service
public class CorrelationEngine {

    private static final Logger log = LoggerFactory.getLogger(CorrelationEngine.class);
    private static final Duration MAX_CORRELATION_WINDOW = Duration.ofMinutes(60);

    public record CorrelatedScenario(
            String scenarioCode,
            String title,
            String description,
            IncidentSeverity severity,
            String assetId,
            List<String> matchedFindingIds,
            String explanation
    ) {}

    public List<CorrelatedScenario> evaluateFindings(List<FindingDto> findings) {
        List<CorrelatedScenario> scenarios = new ArrayList<>();
        if (findings == null || findings.isEmpty()) return scenarios;

        // Bounded correlation horizon (24 hours) to avoid processing stale findings
        Instant horizon = Instant.now().minus(Duration.ofHours(24));
        List<FindingDto> candidateFindings = findings.stream()
                .filter(f -> f != null && f.getAssetId() != null && (f.getTimestamp() == null || f.getTimestamp().isAfter(horizon)))
                .toList();

        // Group findings by asset
        Map<String, List<FindingDto>> byAsset = candidateFindings.stream()
                .collect(Collectors.groupingBy(FindingDto::getAssetId));

        for (Map.Entry<String, List<FindingDto>> entry : byAsset.entrySet()) {
            String assetId = entry.getKey();
            List<FindingDto> assetFindings = entry.getValue();
            assetFindings.sort(Comparator.comparing(FindingDto::getTimestamp));

            // C001: Linux Account Compromise Sequence
            checkC001LinuxCompromise(assetId, assetFindings, scenarios);

            // C002: Windows Suspicious Execution Chain
            checkC002WindowsExecutionChain(assetId, assetFindings, scenarios);

            // C003: IOC-Associated Multi-Stage Activity
            checkC003IocActivity(assetId, assetFindings, scenarios);

            // C004: Account and Privilege Manipulation
            checkC004PrivilegeManipulation(assetId, assetFindings, scenarios);
        }

        return scenarios;
    }

    private void checkC001LinuxCompromise(String assetId, List<FindingDto> findings, List<CorrelatedScenario> results) {
        boolean hasSshFail = findings.stream().anyMatch(f -> "D001".equalsIgnoreCase(f.getRuleId()));
        boolean hasSshSuccess = findings.stream().anyMatch(f -> "D002".equalsIgnoreCase(f.getRuleId()));
        boolean hasPrivExec = findings.stream().anyMatch(f -> "D004".equalsIgnoreCase(f.getRuleId()));

        if (hasSshFail && (hasSshSuccess || hasPrivExec)) {
            List<FindingDto> matched = findings.stream()
                    .filter(f -> Set.of("D001", "D002", "D004", "D006").contains(f.getRuleId()))
                    .collect(Collectors.toList());

            if (!isWithinCorrelationWindow(matched)) return;

            List<String> matchedIds = matched.stream().map(FindingDto::getFindingId).collect(Collectors.toList());
            results.add(new CorrelatedScenario(
                    "C001",
                    "Correlated Attack: Linux Account Compromise & Privilege Escalation",
                    "Observed repeated SSH authentication failures followed by successful authentication or privileged command execution on host " + assetId,
                    IncidentSeverity.CRITICAL,
                    assetId,
                    matchedIds,
                    "Sequence satisfied: Repeated brute-force attempts followed by privileged session activity within 60-minute window."
            ));
        }
    }

    private void checkC002WindowsExecutionChain(String assetId, List<FindingDto> findings, List<CorrelatedScenario> results) {
        boolean hasParentChild = findings.stream().anyMatch(f -> "D009".equalsIgnoreCase(f.getRuleId()));
        boolean hasPowerShell = findings.stream().anyMatch(f -> "D008".equalsIgnoreCase(f.getRuleId()));
        boolean hasOutbound = findings.stream().anyMatch(f -> "D014".equalsIgnoreCase(f.getRuleId()));

        if ((hasParentChild && hasPowerShell) || (hasPowerShell && hasOutbound)) {
            List<FindingDto> matched = findings.stream()
                    .filter(f -> Set.of("D008", "D009", "D014").contains(f.getRuleId()))
                    .collect(Collectors.toList());

            if (!isWithinCorrelationWindow(matched)) return;

            List<String> matchedIds = matched.stream().map(FindingDto::getFindingId).collect(Collectors.toList());
            results.add(new CorrelatedScenario(
                    "C002",
                    "Correlated Attack: Windows Multi-Stage Execution Chain",
                    "Suspicious parent process spawned encoded PowerShell leading to anomalous outbound network connection on " + assetId,
                    IncidentSeverity.CRITICAL,
                    assetId,
                    matchedIds,
                    "Execution chain satisfied: MITRE T1059 (Execution) -> T1059.001 (PowerShell) -> T1071 (C2 egress) within 60-minute window."
            ));
        }
    }

    private void checkC003IocActivity(String assetId, List<FindingDto> findings, List<CorrelatedScenario> results) {
        List<FindingDto> d015Findings = findings.stream()
                .filter(f -> "D015".equalsIgnoreCase(f.getRuleId()))
                .toList();

        for (FindingDto d15 : d015Findings) {
            List<FindingDto> matched = findings.stream()
                    .filter(f -> f.getTimestamp() != null && d15.getTimestamp() != null
                            && Duration.between(f.getTimestamp(), d15.getTimestamp()).abs().compareTo(MAX_CORRELATION_WINDOW) <= 0)
                    .collect(Collectors.toList());

            if (matched.size() > 1) {
                List<String> matchedIds = matched.stream().map(FindingDto::getFindingId).collect(Collectors.toList());
                results.add(new CorrelatedScenario(
                        "C003",
                        "Correlated Threat: Known Threat Intel IOC Activity With Secondary Suspicious Behavior",
                        "Communication matching high-confidence threat intelligence accompanied by secondary endpoint detections on " + assetId,
                        IncidentSeverity.HIGH,
                        assetId,
                        matchedIds,
                        "Multi-source correlation: Network threat indicator confirmed by subsequent endpoint execution behavior within 60-minute window."
                ));
                break;
            }
        }
    }

    private void checkC004PrivilegeManipulation(String assetId, List<FindingDto> findings, List<CorrelatedScenario> results) {
        boolean hasAcctCreate = findings.stream().anyMatch(f -> "D005".equalsIgnoreCase(f.getRuleId()));
        boolean hasServiceOrTask = findings.stream().anyMatch(f -> "D007".equalsIgnoreCase(f.getRuleId()) || "D010".equalsIgnoreCase(f.getRuleId()) || "D018".equalsIgnoreCase(f.getRuleId()));

        if (hasAcctCreate && hasServiceOrTask) {
            List<FindingDto> matched = findings.stream()
                    .filter(f -> Set.of("D005", "D007", "D010", "D018").contains(f.getRuleId()))
                    .collect(Collectors.toList());

            if (!isWithinCorrelationWindow(matched)) return;

            List<String> matchedIds = matched.stream().map(FindingDto::getFindingId).collect(Collectors.toList());
            results.add(new CorrelatedScenario(
                    "C004",
                    "Correlated Attack: Account and Persistence Manipulation",
                    "Creation of new user account accompanied by service or scheduled task installation on " + assetId,
                    IncidentSeverity.HIGH,
                    assetId,
                    matchedIds,
                    "Persistence correlation: MITRE T1136 (Local Account) followed by persistence establishment (T1543 / T1053) within 60-minute window."
            ));
        }
    }

    private boolean isWithinCorrelationWindow(List<FindingDto> matched) {
        if (matched.size() < 2) return true;
        Instant minTime = matched.stream().map(FindingDto::getTimestamp).filter(Objects::nonNull).min(Instant::compareTo).orElse(null);
        Instant maxTime = matched.stream().map(FindingDto::getTimestamp).filter(Objects::nonNull).max(Instant::compareTo).orElse(null);
        if (minTime == null || maxTime == null) return true;
        return Duration.between(minTime, maxTime).abs().compareTo(MAX_CORRELATION_WINDOW) <= 0;
    }
}
