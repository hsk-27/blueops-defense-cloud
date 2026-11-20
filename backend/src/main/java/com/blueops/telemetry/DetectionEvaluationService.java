package com.blueops.telemetry;

import com.blueops.assets.Asset;
import com.blueops.assets.AssetRepository;
import com.blueops.assets.AssetService;
import com.blueops.detections.correlation.CorrelationEngine;
import com.blueops.findings.FindingDto;
import com.blueops.findings.OpenSearchFindingAdapter;
import com.blueops.incidents.*;
import com.blueops.threatintel.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.*;
import java.util.concurrent.atomic.AtomicLong;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

@Service
public class DetectionEvaluationService {

    private static final Logger log = LoggerFactory.getLogger(DetectionEvaluationService.class);

    private final IocIndicatorRepository iocRepository;
    private final IocMatchRepository matchRepository;
    private final OpenSearchFindingAdapter findingAdapter;
    private final CorrelationEngine correlationEngine;
    private final IncidentService incidentService;
    private final IncidentRepository incidentRepository;
    private final AssetRepository assetRepository;
    private final AssetService assetService;
    private final com.blueops.detections.sigma.SigmaDetectionEvaluator sigmaDetectionEvaluator;

    private final AtomicLong findingSeq = new AtomicLong(1000);

    // Regex patterns for deceptive and obfuscated attack detection
    private static final Pattern POWERSHELL_ENCODED = Pattern.compile("(?i)(powershell|pwsh)(\\.exe)?.*(-e|-enc|-encodedcommand|-eNCoDeDCoMmAnD)\\s+[A-Za-z0-9+/=]{10,}");
    private static final Pattern POWERSHELL_DOWNLOAD = Pattern.compile("(?i)(DownloadString|DownloadFile|IEX|Invoke-Expression|Net\\.WebClient|curl|wget)");
    private static final Pattern OFFICE_PARENT = Pattern.compile("(?i)(winword|excel|powerpnt|outlook|eqnedt32)\\.exe");
    private static final Pattern CMD_CHILD = Pattern.compile("(?i)(cmd|powershell|pwsh|wscript|cscript|mshta|rundll32|regsvr32)\\.exe");
    private static final Pattern MIMIKATZ_LSASS = Pattern.compile("(?i)(mimikatz|sekurlsa|procdump|lsass\\.dmp|comsvcs(\\.dll)?.*MiniDump)");
    private static final Pattern LOG_CLEARING = Pattern.compile("(?i)(wevtutil(\\.exe)?\\s+cl|Clear-EventLog|Limit-EventLog)");
    private static final Pattern SUDO_ROOT_SHELL = Pattern.compile("(?i)sudo\\s+(/bin/)?(bash|sh|zsh|dash|-i|su)");
    private static final Pattern AUDITCTL_DISABLE = Pattern.compile("(?i)auditctl\\s+(-D|--delete-all)");
    private static final Pattern USER_ADD = Pattern.compile("(?i)(useradd|adduser|net\\s+user\\s+/add)");
    private static final Pattern SCHTASKS_CREATE = Pattern.compile("(?i)schtasks(\\.exe)?\\s+/create");
    private static final Pattern SC_CREATE = Pattern.compile("(?i)sc(\\.exe)?\\s+create");

    @Autowired
    public DetectionEvaluationService(
            IocIndicatorRepository iocRepository,
            IocMatchRepository matchRepository,
            OpenSearchFindingAdapter findingAdapter,
            CorrelationEngine correlationEngine,
            IncidentService incidentService,
            IncidentRepository incidentRepository,
            AssetRepository assetRepository,
            @Autowired(required = false) AssetService assetService,
            @Autowired(required = false) com.blueops.detections.sigma.SigmaDetectionEvaluator sigmaDetectionEvaluator) {
        this.iocRepository = iocRepository;
        this.matchRepository = matchRepository;
        this.findingAdapter = findingAdapter;
        this.correlationEngine = correlationEngine;
        this.incidentService = incidentService;
        this.incidentRepository = incidentRepository;
        this.assetRepository = assetRepository;
        this.assetService = assetService;
        this.sigmaDetectionEvaluator = sigmaDetectionEvaluator;
    }

    public DetectionEvaluationService(
            IocIndicatorRepository iocRepository,
            IocMatchRepository matchRepository,
            OpenSearchFindingAdapter findingAdapter,
            CorrelationEngine correlationEngine,
            IncidentService incidentService,
            IncidentRepository incidentRepository,
            AssetRepository assetRepository) {
        this(iocRepository, matchRepository, findingAdapter, correlationEngine, incidentService, incidentRepository, assetRepository, null, null);
    }

    @Transactional
    public List<FindingDto> evaluate(NormalizedEvent event) {
        List<FindingDto> triggeredFindings = new ArrayList<>();
        if (event == null) return triggeredFindings;

        String assetId = event.getHost() != null ? event.getHost().getId() : "WIN-ASSET-001";
        String assetName = event.getHost() != null ? event.getHost().getName() : "LAB-HOST";
        String hostIp = event.getHost() != null ? event.getHost().getIp() : "192.168.56.101";

        // Resolve Asset Entity and record telemetry heartbeat
        Asset asset;
        if (assetService != null) {
            asset = assetService.recordTelemetryHeartbeat(
                    assetId, assetName, hostIp,
                    event.getHost() != null ? event.getHost().getOsName() : null
            );
        } else {
            asset = assetRepository.findByPersistentId(assetId)
                    .or(() -> assetRepository.findByHostname(assetName))
                    .or(() -> assetRepository.findByIpAddress(hostIp))
                    .orElse(null);
        }

        // 1. Threat Intelligence IOC Matching
        evaluateThreatIntel(event, asset, triggeredFindings);

        // 2. Built-in Sigma Detection Rules Evaluation
        evaluateSigmaRules(event, assetId, assetName, triggeredFindings);

        // 3. Dynamic Sigma Rule Engine Evaluation (DET-001)
        if (sigmaDetectionEvaluator != null) {
            List<FindingDto> dynamicFindings = sigmaDetectionEvaluator.evaluate(event, assetId, assetName);
            Set<String> existingRuleCodes = triggeredFindings.stream()
                    .map(FindingDto::getRuleId)
                    .collect(Collectors.toSet());
            for (FindingDto df : dynamicFindings) {
                if (df != null && !existingRuleCodes.contains(df.getRuleId())) {
                    triggeredFindings.add(df);
                    existingRuleCodes.add(df.getRuleId());
                }
            }
        }

        // 3. Register triggered findings into OpenSearch Finding Adapter
        for (FindingDto finding : triggeredFindings) {
            findingAdapter.registerFinding(finding);
            log.info("Rule triggered: [{}] {} on asset {} (Finding ID: {})",
                    finding.getRuleId(), finding.getRuleName(), assetId, finding.getFindingId());
        }

        // 4. Multi-Stage Correlation Engine
        evaluateCorrelation(assetId, asset);

        return triggeredFindings;
    }

    private void evaluateThreatIntel(NormalizedEvent event, Asset asset, List<FindingDto> findings) {
        List<String> candidateIndicators = new ArrayList<>();
        if (event.getDestination() != null) {
            if (event.getDestination().getIp() != null) candidateIndicators.add(event.getDestination().getIp().trim());
            if (event.getDestination().getDomain() != null) candidateIndicators.add(event.getDestination().getDomain().trim());
        }
        if (event.getSource() != null && event.getSource().getIp() != null) {
            candidateIndicators.add(event.getSource().getIp().trim());
        }
        if (event.getProcess() != null && event.getProcess().getHashSha256() != null) {
            candidateIndicators.add(event.getProcess().getHashSha256().trim());
        }
        if (event.getFile() != null && event.getFile().getHashSha256() != null) {
            candidateIndicators.add(event.getFile().getHashSha256().trim());
        }
        if (event.getRelatedIps() != null) {
            for (String ip : event.getRelatedIps()) {
                if (ip != null && !ip.isBlank()) candidateIndicators.add(ip.trim());
            }
        }
        if (event.getRelatedHashes() != null) {
            for (String hash : event.getRelatedHashes()) {
                if (hash != null && !hash.isBlank()) candidateIndicators.add(hash.trim());
            }
        }

        for (String cand : candidateIndicators) {
            if (cand.isEmpty() || "127.0.0.1".equals(cand) || "0.0.0.0".equals(cand)) continue;

            Optional<IocIndicator> iocOpt = iocRepository.findByIndicatorValueIgnoreCase(cand);
            if (iocOpt.isPresent()) {
                IocIndicator ioc = iocOpt.get();
                if ("ACTIVE".equalsIgnoreCase(ioc.getStatus())) {
                    // Record IOC Match
                    IocMatch match = new IocMatch(
                            ioc, cand, asset, event.getTimestamp(), event.getId(), "network.destination.ip/domain/hash"
                    );
                    matchRepository.save(match);
                    ioc.setLastSeenAt(Instant.now());
                    iocRepository.save(ioc);

                    // Create D015 Finding
                    String fId = "FND-IOC-" + findingSeq.incrementAndGet();
                    FindingDto finding = new FindingDto(
                            fId, "D015", "Connection to Known Threat Intelligence Indicator: " + cand,
                            ioc.getSeverity() != null ? ioc.getSeverity() : "HIGH",
                            "Command and Control", "T1071", "Application Layer Protocol",
                            asset != null ? asset.getPersistentId() : "WIN-ASSET-001",
                            asset != null ? asset.getHostname() : "LAB-HOST",
                            event.getTimestamp(), "UNASSIGNED", event.getId(),
                            Map.of("matched_indicator", cand, "source", ioc.getSource(), "confidence", ioc.getConfidence(), "threat_type", ioc.getIndicatorType().name())
                    );
                    findings.add(finding);
                }
            }
        }
    }

    private void evaluateSigmaRules(NormalizedEvent event, String assetId, String assetName, List<FindingDto> findings) {
        String procCmd = event.getProcess() != null && event.getProcess().getCommandLine() != null ? event.getProcess().getCommandLine() : "";
        String procName = event.getProcess() != null && event.getProcess().getName() != null ? event.getProcess().getName() : "";
        String parentName = event.getProcess() != null && event.getProcess().getParent() != null && event.getProcess().getParent().getName() != null
                ? event.getProcess().getParent().getName() : "";
        String action = event.getEvent() != null && event.getEvent().getAction() != null ? event.getEvent().getAction() : "";
        String original = event.getEvent() != null && event.getEvent().getOriginal() != null ? event.getEvent().getOriginal() : "";

        // D007: Suspicious System Service Creation (Linux, T1543.002)
        if ((event.getFile() != null && event.getFile().getPath() != null && event.getFile().getPath().contains("/etc/systemd/system"))
                || procCmd.contains("/etc/systemd/system")
                || (procCmd.contains("systemctl") && procCmd.contains("enable") && !procCmd.contains("/lib/systemd"))) {
            findings.add(createFinding("D007", "Suspicious System Service Creation in /etc/systemd/system", "MEDIUM",
                    "Persistence", "T1543.002", "Systemd Service", assetId, assetName, event,
                    Map.of("command_line", procCmd)));
        }

        // D008: Suspicious Encoded PowerShell Execution or Download Cradle (Windows, T1059.001)
        boolean isPowerShellProc = procCmd.toLowerCase().contains("powershell") || procName.toLowerCase().contains("powershell")
                || procCmd.toLowerCase().contains("pwsh") || procName.toLowerCase().contains("pwsh");
        boolean isEncodedPs = POWERSHELL_ENCODED.matcher(procCmd).find() || (procCmd.toLowerCase().contains("powershell") && procCmd.contains("-e ") && procCmd.length() > 30);
        boolean isDownloadCradle = isPowerShellProc && POWERSHELL_DOWNLOAD.matcher(procCmd).find();

        if (isEncodedPs || isDownloadCradle) {
            findings.add(createFinding("D008", isDownloadCradle && !isEncodedPs ? "PowerShell Download Cradle / Unencoded Execution" : "Suspicious Encoded PowerShell Execution", "HIGH",
                    "Execution", "T1059.001", "PowerShell", assetId, assetName, event,
                    Map.of("command_line", procCmd, "process_name", procName, "cradle_detected", isDownloadCradle)));
        }

        // D009: Office Application Spawning Command Interpreter (Windows, T1059)
        if (OFFICE_PARENT.matcher(parentName).find() && CMD_CHILD.matcher(procName).find()) {
            findings.add(createFinding("D009", "Office Application Spawning Command Interpreter", "HIGH",
                    "Execution", "T1059", "Command and Scripting Interpreter", assetId, assetName, event,
                    Map.of("parent_process", parentName, "spawned_process", procName, "command_line", procCmd)));
        }

        // D010: Scheduled Task Creation via Command Line (Windows, T1053.005)
        if (SCHTASKS_CREATE.matcher(procCmd).find()) {
            findings.add(createFinding("D010", "Scheduled Task Creation via Command Line", "MEDIUM",
                    "Persistence", "T1053.005", "Scheduled Task", assetId, assetName, event,
                    Map.of("command_line", procCmd)));
        }

        // D011: Local Security Authority Subsystem Service (LSASS) Memory Access (Windows, T1003.001)
        if (MIMIKATZ_LSASS.matcher(procCmd).find() || MIMIKATZ_LSASS.matcher(procName).find()
                || (procCmd.toLowerCase().contains("comsvcs") && procCmd.toLowerCase().contains("minidump"))) {
            findings.add(createFinding("D011", "LSASS Memory Dumping / Credential Harvesting", "CRITICAL",
                    "Credential Access", "T1003.001", "LSASS Memory", assetId, assetName, event,
                    Map.of("command_line", procCmd, "tool_pattern", "Mimikatz/ProcDump/Comsvcs signature")));
        }

        // D012: Unexpected Driver Loading (Windows/Linux, T1543.003)
        if ("driver_loaded".equalsIgnoreCase(action)
                || (event.getFile() != null && event.getFile().getPath() != null && event.getFile().getPath().toLowerCase().endsWith(".sys")
                    && !event.getFile().getPath().toLowerCase().contains("c:\\windows\\system32\\drivers"))
                || procCmd.toLowerCase().contains("fltmc load")
                || procCmd.toLowerCase().contains("insmod ")
                || procCmd.toLowerCase().contains("modprobe ")) {
            findings.add(createFinding("D012", "Unexpected Kernel Driver Loading Activity", "HIGH",
                    "Persistence", "T1543.003", "Kernel Drivers", assetId, assetName, event,
                    Map.of("action", action, "command_line", procCmd)));
        }

        // D013: Security Event Log Clearing (Windows, T1070.001)
        if (LOG_CLEARING.matcher(procCmd).find() || procCmd.contains("wevtutil cl") || procCmd.contains("Clear-EventLog")) {
            findings.add(createFinding("D013", "Security Event Log Clearing Activity", "CRITICAL",
                    "Defense Evasion", "T1070.001", "Clear Windows Event Logs", assetId, assetName, event,
                    Map.of("command_line", procCmd)));
        }

        // D014: Outbound Network Connection to Non-Standard High Port (Network/Suricata, T1071.001)
        if (event.getDestination() != null && event.getDestination().getPort() != null) {
            int port = event.getDestination().getPort();
            if (Set.of(4444, 1337, 8888, 9001, 6667, 31337).contains(port)) {
                findings.add(createFinding("D014", "Outbound Connection to Non-Standard High/Malicious Port (" + port + ")", "MEDIUM",
                        "Command and Control", "T1071.001", "Web Protocols", assetId, assetName, event,
                        Map.of("destination_ip", event.getDestination().getIp(), "destination_port", port)));
            }
        }

        // D016: Protected-File Modification (Windows/Linux, T1565.001 / T1547.001)
        boolean isHostsMod = (event.getFile() != null && event.getFile().getPath() != null
                && (event.getFile().getPath().toLowerCase().contains("drivers\\etc\\hosts") || event.getFile().getPath().contains("/etc/hosts")))
                || procCmd.toLowerCase().contains("drivers\\etc\\hosts") || procCmd.contains("/etc/hosts");
        boolean isRegistryRun = (event.getRegistry() != null && event.getRegistry().getPath() != null
                && (event.getRegistry().getPath().toLowerCase().contains("currentversion\\run")
                    || event.getRegistry().getPath().toLowerCase().contains("currentversion\\runonce")));

        if (isHostsMod || isRegistryRun) {
            findings.add(createFinding("D016", "Protected-File / System Key Modification", "HIGH",
                    "Impact", "T1565.001", "Stored Data Manipulation", assetId, assetName, event,
                    Map.of("target", isHostsMod ? "hosts_file" : "registry_run_key", "command_line", procCmd)));
        }

        // D017: Repeated Authentication Failures From a Single Source (Network/Auth, T1110)
        boolean isAuthCategory = event.getEvent() != null && event.getEvent().getCategory() != null
                && event.getEvent().getCategory().contains("authentication");
        boolean isAuthFail = action.contains("failed_login") || original.contains("res=failed")
                || original.contains("authentication failure") || action.contains("failure");

        if ((isAuthCategory && isAuthFail) || (event.getSource() != null && event.getSource().getIp() != null && isAuthFail)) {
            findings.add(createFinding("D017", "Repeated Authentication Failures From Single Source", "MEDIUM",
                    "Credential Access", "T1110", "Brute Force", assetId, assetName, event,
                    Map.of("source_ip", event.getSource() != null ? event.getSource().getIp() : "unknown", "action", action)));
        }

        // D001: Repeated SSH Authentication Failures (Linux, T1110)
        if (action.contains("failed_login") || original.contains("res=failed") || original.contains("authentication failure")) {
            findings.add(createFinding("D001", "Linux Authentication Failure / Potential Brute Force", "LOW",
                    "Credential Access", "T1110", "Brute Force", assetId, assetName, event,
                    Map.of("raw_action", action, "user", event.getUser() != null ? event.getUser().getName() : "unknown")));
        }

        // D002: Successful SSH Authentication Following Failures (Linux, T1078)
        if (action.contains("successful_login") || (original.contains("res=success") && original.contains("sshd"))) {
            findings.add(createFinding("D002", "Linux Successful Authentication", "MEDIUM",
                    "Initial Access", "T1078", "Valid Accounts", assetId, assetName, event,
                    Map.of("raw_action", action, "user", event.getUser() != null ? event.getUser().getName() : "unknown")));
        }

        // D003: Sudo Execution Without TTY (Linux, T1548.003)
        if (original.contains("tty=(none)") && procCmd.contains("sudo")) {
            findings.add(createFinding("D003", "Sudo Execution Without Controlling TTY", "HIGH",
                    "Privilege Escalation", "T1548.003", "Sudo and Sudo Caching", assetId, assetName, event,
                    Map.of("command_line", procCmd, "tty", "none")));
        }

        // D004: Interactive Root Shell Spawned From Sudo (Linux, T1548.003)
        if (SUDO_ROOT_SHELL.matcher(procCmd).find()) {
            findings.add(createFinding("D004", "Interactive Root Shell Spawned via Sudo", "HIGH",
                    "Privilege Escalation", "T1548.003", "Sudo and Sudo Caching", assetId, assetName, event,
                    Map.of("command_line", procCmd, "user", event.getUser() != null ? event.getUser().getName() : "root")));
        }

        // D005: Creation of Unauthorized Local User Account (Linux/Windows, T1136.001)
        if (USER_ADD.matcher(procCmd).find()) {
            findings.add(createFinding("D005", "Creation of Unauthorized Local User Account", "MEDIUM",
                    "Persistence", "T1136.001", "Local Account", assetId, assetName, event,
                    Map.of("command_line", procCmd)));
        }

        // D006: Linux Audit Log Configuration Modification (Linux, T1562.001)
        if (AUDITCTL_DISABLE.matcher(procCmd).find() || procCmd.contains("/etc/audit/audit.rules")) {
            findings.add(createFinding("D006", "Linux Audit Subsystem Tampering (auditctl -D)", "HIGH",
                    "Defense Evasion", "T1562.001", "Disable or Modify Tools", assetId, assetName, event,
                    Map.of("command_line", procCmd)));
        }

        // D018: Defense Evasion / Administrative Service Activity (Windows, T1569.002 / T1036)
        if (SC_CREATE.matcher(procCmd).find() || procCmd.toLowerCase().contains("sc.exe create") || procCmd.toLowerCase().contains("new-service")
                || (procName.equalsIgnoreCase("svchost.exe") && procCmd.length() > 0 && !procCmd.toLowerCase().contains("c:\\windows\\system32"))) {
            findings.add(createFinding("D018", "Unusual Administrative Service Activity or Service Masquerading", "HIGH",
                    "Persistence", "T1569.002", "Service Execution", assetId, assetName, event,
                    Map.of("command_line", procCmd, "process_name", procName)));
        }
    }

    private FindingDto createFinding(String ruleId, String ruleName, String severity,
                                     String tactic, String techId, String techName,
                                     String assetId, String assetName,
                                     NormalizedEvent event, Map<String, Object> details) {
        String fId = "FND-" + ruleId + "-" + findingSeq.incrementAndGet();
        return new FindingDto(
                fId, ruleId, ruleName, severity, tactic, techId, techName,
                assetId, assetName, event.getTimestamp(), "UNASSIGNED", event.getId(), details
        );
    }

    private void evaluateCorrelation(String assetId, Asset asset) {
        try {
            List<FindingDto> allFindings = findingAdapter.fetchFindings();
            List<CorrelationEngine.CorrelatedScenario> scenarios = correlationEngine.evaluateFindings(allFindings);

            for (CorrelationEngine.CorrelatedScenario sc : scenarios) {
                if (!sc.assetId().equalsIgnoreCase(assetId)) continue;

                Long assetDbId = asset != null ? asset.getId() : null;
                List<Incident> activeIncidents = incidentRepository.findActiveByTitleAndAsset(sc.title(), assetDbId);

                if (activeIncidents.isEmpty()) {
                    // Automatically generate incident for this correlated attack scenario
                    IncidentCreateRequest req = new IncidentCreateRequest();
                    req.setTitle(sc.title());
                    req.setDescription(sc.description() + "\n\nCorrelation Explanation: " + sc.explanation());
                    req.setSeverity(sc.severity());
                    if (asset != null) {
                        req.setPrimaryAssetId(asset.getId());
                    }
                    req.setFindingIds(sc.matchedFindingIds());

                    IncidentDto incident = incidentService.createIncident(req, "system:correlation-engine");
                    log.warn(">>> CORRELATION ENGINE AUTO-TRIGGERED INCIDENT: [{}] {} (ID: {}) on asset {}",
                            sc.scenarioCode(), sc.title(), incident.getIncidentNumber(), assetId);

                    // Add automated triage note
                    IncidentNoteRequest note = new IncidentNoteRequest();
                    note.setNoteText("Automated Correlation Engine: Detected sequence of " + sc.matchedFindingIds().size() +
                            " security findings matching scenario " + sc.scenarioCode() + " within the correlation window.");
                    incidentService.addNote(incident.getId(), note, "system:correlation-engine");
                } else {
                    // Existing active incident: link newly observed findings in this attack chain
                    Incident existing = activeIncidents.get(0);
                    Set<String> attachedIds = existing.getFindings().stream()
                            .map(IncidentFinding::getOpensearchFindingId)
                            .collect(Collectors.toSet());
                    List<String> newIds = new ArrayList<>();
                    for (String fid : sc.matchedFindingIds()) {
                        if (!attachedIds.contains(fid)) {
                            Optional<FindingDto> findingOpt = findingAdapter.getFindingById(fid);
                            if (findingOpt.isPresent()) {
                                FindingDto f = findingOpt.get();
                                IncidentFinding incFinding = new IncidentFinding(
                                        existing, f.getFindingId(), f.getRuleId(), f.getRuleName(),
                                        f.getRuleSeverity(), f.getTimestamp(), f.getRelatedDocId(),
                                        f.getDetails() != null ? f.getDetails().toString() : null
                                );
                                existing.getFindings().add(incFinding);
                                f.setStatus("LINKED_TO_INCIDENT");
                                newIds.add(fid);
                            }
                        }
                    }
                    if (!newIds.isEmpty()) {
                        existing.setUpdatedAt(Instant.now());
                        incidentRepository.save(existing);
                        IncidentNoteRequest note = new IncidentNoteRequest();
                        note.setNoteText("Correlation Engine Update: Associated additional findings: " +
                                String.join(", ", newIds));
                        incidentService.addNote(existing.getId(), note, "system:correlation-engine");
                        log.info("Appended new findings to active incident {}: {}", existing.getIncidentNumber(), newIds);
                    }
                }
            }
        } catch (Exception ex) {
            log.error("Failed to run correlation evaluation: {}", ex.getMessage(), ex);
        }
    }
}
