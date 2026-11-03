package com.blueops.advisory;

import org.springframework.stereotype.Component;

import java.util.*;

/**
 * Authoritative Knowledge Base for Incident Response Recommendations.
 * Encapsulates formal guidance and procedural playbooks derived strictly from:
 * - NIST SP 800-61 Rev. 2 (Computer Security Incident Handling Guide)
 * - CISA Federal Incident Response Playbooks (Nov 2021 / 2023)
 * - MITRE ATT&CK Mitigations & MITRE D3FEND Countermeasures Matrix
 * - SANS PICERL & RFC 3227 Order of Volatility
 */
@Component
public class AdvisoryKnowledgeBase {

    public record AdvisoryRule(
            String id,
            String title,
            AdvisoryPhase phase,
            AdvisoryPriority priority,
            AuthoritativeSource source,
            String citation,
            String rationaleTemplate,
            List<String> steps,
            String suggestedPlaybookCode,
            String suggestedPlaybookName,
            Set<String> triggerTechniques,
            Set<String> triggerRuleCodes
    ) {}

    private final List<AdvisoryRule> catalog = new ArrayList<>();

    public AdvisoryKnowledgeBase() {
        initializeCatalog();
    }

    private void initializeCatalog() {
        // 1. C2 Network Egress -> Perimeter Firewall Block (CISA / MITRE D3FEND)
        catalog.add(new AdvisoryRule(
                "ADV-NET-001",
                "Apply Perimeter Drop Rule for Malicious C2 Communication",
                AdvisoryPhase.CONTAINMENT,
                AdvisoryPriority.IMMEDIATE_ACTION,
                AuthoritativeSource.CISA_IR_PLAYBOOK,
                "CISA IR Playbook §3.3 (Network Perimeter Containment) & MITRE D3FEND D3-NTF",
                "Detected adversary command-and-control communication or known IOC egress. In accordance with CISA IR Playbook Section 3.3, outbound and inbound connectivity to identified threat infrastructure must be blocked at the perimeter to sever adversary control and payload staging.",
                List.of(
                        "Verify matched destination IP/Domain against threat intelligence feeds.",
                        "Apply perimeter firewall drop rule to sever egress communication.",
                        "Inspect DNS query logs across all internal endpoints for historical beaconing to this indicator.",
                        "Review proxy and NetFlow telemetry for related high-port connections (4444, 1337, 8888)."
                ),
                "P001",
                "Block Suspicious Lab IP",
                Set.of("T1071", "T1071.001"),
                Set.of("D014", "D015")
        ));

        // 2. Credential Dumping / Brute Force -> Account Disabling & Session Revocation (NIST / MITRE)
        catalog.add(new AdvisoryRule(
                "ADV-IAM-001",
                "Invalidate Sessions and Disable Potentially Compromised Accounts",
                AdvisoryPhase.CONTAINMENT,
                AdvisoryPriority.IMMEDIATE_ACTION,
                AuthoritativeSource.NIST_SP_800_61R2,
                "NIST SP 800-61r2 §3.3.1 (Containment Strategy) & MITRE ATT&CK M1018",
                "Observed credential dumping (LSASS memory access) or repeated authentication spray patterns. NIST SP 800-61r2 Section 3.3.1 advises immediate session termination and credential disabling to prevent unauthorized lateral movement and privilege escalation across corporate assets.",
                List.of(
                        "Temporarily lock and disable target user account credentials.",
                        "Terminate active Kerberos TGT tickets, OAuth refresh tokens, and interactive RDP/SSH sessions.",
                        "Enforce password rotation and verify Multi-Factor Authentication (MFA) tokens.",
                        "Audit domain controller logs for anomalous authentications originating from this account within the last 24 hours."
                ),
                "P002",
                "Disable Compromised Test Account",
                Set.of("T1003.001", "T1110", "T1110.001", "T1110.003", "T1078"),
                Set.of("D001", "D002", "D003", "D011", "D017")
        ));

        // 3. Active Execution / Living-off-the-Land -> Dynamic Endpoint Isolation (CISA / SANS)
        catalog.add(new AdvisoryRule(
                "ADV-END-001",
                "Execute Dynamic Network Isolation on Compromised Endpoint",
                AdvisoryPhase.CONTAINMENT,
                AdvisoryPriority.IMMEDIATE_ACTION,
                AuthoritativeSource.CISA_IR_PLAYBOOK,
                "CISA IR Playbook §3.1 (Endpoint Quarantining) & SANS PICERL Step 3",
                "Observed suspicious command interpreter execution, encoded PowerShell payloads, or binary masquerading. SANS PICERL Step 3 and CISA Playbook Step 3.1 mandate isolating the affected endpoint from the corporate LAN while preserving SOC management tunnels to prevent adversary lateral spread.",
                List.of(
                        "Isolate the endpoint from the production VLAN, routing only management/SOC telemetry.",
                        "Preserve volatile system state; avoid rebooting or powering down the machine.",
                        "Notify endpoint primary user and system owner of active containment protocol.",
                        "Monitor host firewall telemetry to ensure lateral egress packets are dropped."
                ),
                "P003",
                "Isolate Suspicious Lab Endpoint",
                Set.of("T1059", "T1059.001", "T1036", "T1543.003"),
                Set.of("D008", "D009", "D012", "D018")
        ));

        // 4. Volatile Artifacts / Memory Dumping -> Forensic Evidence Acquisition (RFC 3227 / NIST)
        catalog.add(new AdvisoryRule(
                "ADV-FOR-001",
                "Acquire Volatile Memory Dump and Forensic Event Traces",
                AdvisoryPhase.DETECTION_AND_ANALYSIS,
                AdvisoryPriority.HIGH_PRIORITY,
                AuthoritativeSource.RFC_3227,
                "IETF RFC 3227 (Order of Volatility) & NIST SP 800-61r2 §3.3.2 (Evidence Gathering)",
                "Evidence gathering must adhere to RFC 3227 order of volatility: volatile RAM, active network sockets, and running process tables must be acquired before disk persistence or rebooting destroys critical forensic indicators.",
                List.of(
                        "Dispatch agent evidence collection to acquire running process memory and volatile ARP/routing tables.",
                        "Export Sysmon / Linux auditd event streams for the 2-hour window surrounding initial detection.",
                        "Calculate cryptographic SHA256 hashes of all acquired evidence archives to ensure chain-of-custody integrity.",
                        "Store forensic archives in write-protected, isolated evidence storage."
                ),
                "P007",
                "Collect Endpoint Evidence Archive",
                Set.of("T1003.001", "T1059.001", "T1070.001", "T1562.001", "T1562.002"),
                Set.of("D006", "D008", "D011", "D013")
        ));

        // 5. Persistence Establishment -> Eradicate Unauthorized Services & Scheduled Tasks (MITRE D3FEND)
        catalog.add(new AdvisoryRule(
                "ADV-ERA-001",
                "Eradicate Persistence Artifacts and Audit Startup Autoruns",
                AdvisoryPhase.ERADICATION,
                AdvisoryPriority.HIGH_PRIORITY,
                AuthoritativeSource.MITRE_D3FEND,
                "MITRE D3FEND D3-PE (Process Eviction) & D3-FPA (File Path Analysis)",
                "Adversary established persistence via scheduled tasks, systemd unit definitions, or Windows services. MITRE D3FEND requires authoritative eviction of unauthorized processes, deletion of rogue unit files, and verification of autorun registry keys.",
                List.of(
                        "Terminate unauthorized processes spawned by the persistence mechanism.",
                        "Remove malicious systemd unit files from /etc/systemd/system or scheduled tasks created via schtasks.",
                        "Reload daemon configurations (systemctl daemon-reload) and verify service status.",
                        "Inspect registry Run and RunOnce keys for secondary persistence footholds."
                ),
                null,
                null,
                Set.of("T1053.005", "T1543.002", "T1569.002", "T1136.001"),
                Set.of("D005", "D007", "D010", "D018")
        ));

        // 6. Defense Evasion / Tampering -> Re-enable and Verify Audit Subsystems (NIST / CISA)
        catalog.add(new AdvisoryRule(
                "ADV-ERA-002",
                "Restore and Verify Integrity of Endpoint Auditing Subsystems",
                AdvisoryPhase.ERADICATION,
                AdvisoryPriority.HIGH_PRIORITY,
                AuthoritativeSource.NIST_SP_800_61R2,
                "NIST SP 800-61r2 §3.3.4 (Eradication) & CISA CSA (Log Tampering Countermeasures)",
                "Observed clearing of Windows event logs (wevtutil) or disabling of Linux auditd rules (auditctl -D). Tampered logging frameworks must be restored immediately to preserve continuous detection capability and prevent blind spots.",
                List.of(
                        "Re-enable Windows Security Event Log channels and verify maximum log size policies.",
                        "Reload authoritative Linux audit rules from /etc/audit/rules.d/audit.rules (augenrules --load).",
                        "Verify audit daemon health and inspect audit status (auditctl -s).",
                        "Ensure logs are being actively streamed to remote SIEM / OpenSearch collectors."
                ),
                null,
                null,
                Set.of("T1070.001", "T1562.001", "T1562.002"),
                Set.of("D006", "D013")
        ));

        // 7. Post-Incident Review -> Threat Hunting Sweep & Detection Tuning (NIST / SANS)
        catalog.add(new AdvisoryRule(
                "ADV-POST-001",
                "Conduct Enterprise Threat Hunting Sweep and Rule Threshold Calibration",
                AdvisoryPhase.POST_INCIDENT,
                AdvisoryPriority.STRATEGIC_HARDENING,
                AuthoritativeSource.NIST_SP_800_61R2,
                "NIST SP 800-61r2 §3.4 (Lessons Learned) & SANS Incident Handling Step 6",
                "Following containment and resolution, NIST SP 800-61r2 Section 3.4 mandates a structured review to identify gaps in telemetry coverage, tune detection rule sensitivity, and sweep enterprise assets for secondary dormant indicators.",
                List.of(
                        "Conduct an organization-wide threat hunt for all indicators (hashes, IPs, domains) discovered in this incident.",
                        "Review detection latency (MTTD) and containment latency (MTTR) against SOC SLA targets.",
                        "Calibrate Sigma detection rules and false-positive exception filters based on incident telemetry.",
                        "Document incident root-cause analysis and update incident handling playbooks."
                ),
                null,
                null,
                Collections.emptySet(),
                Collections.emptySet()
        ));
    }

    public List<AdvisoryRule> getCatalog() {
        return Collections.unmodifiableList(catalog);
    }
}
