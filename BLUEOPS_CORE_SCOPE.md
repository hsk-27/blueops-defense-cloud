# BLUEOPS CORE SCOPE & BOUNDARY SPECIFICATION

**Document Version:** 2.0.0  
**Classification:** Product Scope, Boundary Control & Acceptance Criteria  
**System Document ID:** BLUEOPS-SCOPE-2026-001  

---

## 1. PURPOSE OF CORE SCOPE DEFINITION

To prevent feature creep, architectural dilution, and superficial dashboard proliferation, this document defines the **immutable boundary of the BlueOps Core Product**.

BlueOps is not an attempt to clone every feature of enterprise SIEM or SOAR platforms. It is an intentional, focused cybersecurity engineering system designed to execute a **single operational spine** with verifiable correctness, cryptographic integrity, and evidence-backed response.

---

## 2. THE MANDATORY MINIMUM VIABLE OPERATIONAL LIFECYCLE (MV-OL)

The fundamental milestone for BlueOps Core is the successful, automated, and repeatable execution of the **16-Step End-to-End Operational Lifecycle**:

```
[1. Benign/Attack Event] ──> [2. Ingestion] ──> [3. Normalization] ──> [4. Provenance]
                                                                             │
[8. Investigation UI] <── [7. Finding Stored] <── [6. Finding Gen] <── [5. Detection]
       │
       └──> [9. Evidence Retrieval] ──> [10. Incident Association] ──> [11. Incident Triage]
                                                                             │
[16. Audit Log] <── [15. Outcome Logged] <── [14. Simulation] <── [13. Policy Check] <── [12. Response Rec]
```

### The 16 Verification Steps
1. **Telemetry Ingestion:** An external or simulated telemetry source submits a raw JSON/Syslog security event (e.g. Sysmon EventID 1 or Linux auditd `USER_AUTH`).
2. **Ingestion Entry:** The event enters `/api/v1/telemetry/ingest` and is received without data loss.
3. **Normalization:** The event is validated and normalized into the Common Event Schema (CES v1.0.0).
4. **Provenance Preservation:** The raw unparsed event is preserved within `event.original` to maintain forensic evidentiary value.
5. **Detection Execution:** The normalized event is evaluated in-process by the `DetectionEvaluationService` against active Sigma rules and IOC tables.
6. **Finding Generation:** If detection criteria match, a `FindingDto` is generated with rule ID, MITRE tactic/technique, severity, and triggering event metadata. (If the event is benign, the pipeline completes without generating a finding).
7. **Finding Storage:** The finding is registered in the finding adapter (in-memory fallback and OpenSearch index).
8. **Investigation Availability:** The finding is immediately retrievable via `GET /api/v1/findings/{id}` or the SOC Investigation Workspace.
9. **Evidence Inspection:** An analyst can inspect the triggering event, host details, user identity, and process hierarchy.
10. **Incident Formation:** The finding is linked to an existing active incident or triggers an automated incident via the Correlation Engine.
11. **Incident Management:** The incident is triaged through state transitions (`NEW` $\rightarrow$ `ASSIGNED` $\rightarrow$ `IN_PROGRESS`) with analyst notes.
12. **Response Recommendation:** The system (or analyst) selects a playbook action (e.g., `isolate_host`, `block_ip`, `disable_user`).
13. **Policy Boundary Validation:** The action request is evaluated by `ResponsePolicyValidator` to ensure the target is not a protected resource (e.g., loopback, gateway, or unauthorized critical asset).
14. **Controlled Simulation:** The action is dispatched to the response agent in `simulation-mode: true`, verifying syntax and execution paths without executing destructive changes.
15. **Outcome Recording:** The response agent returns execution telemetry; a `ResponseExecution` record is created.
16. **Immutable Audit:** The entire sequence from ingestion to simulation is committed to PostgreSQL `AuditLog` entries.

---

## 3. EXPLICIT CORE INCLUSIONS

The BlueOps Core includes exclusively the following functional modules:

### 3.1 Supported Telemetry Sources
1. **Windows Endpoint Telemetry:** Microsoft Sysmon (Event ID 1 Process Create, Event ID 3 Network Connect, Event ID 7 Image Load, Event ID 11 File Create, Event ID 13 Registry, Event ID 1102 / 104 Log Clear).
2. **Linux System Telemetry:** Linux `auditd` (`USER_AUTH`, `SYSCALL`, `EXECVE`, `PROCTITLE`) and `systemd` journal.
3. **Network Security Telemetry:** Suricata Network IDS EVE JSON output (DNS queries, HTTP flows, TLS handshakes, alert records).

### 3.2 Detection Rule Catalog (18 Core Sigma Rules)
- **Linux Rules (D001–D007):** SSH authentication failure brute force, successful login after failure, password spraying, unexpected sudo execution, privileged account creation, auditctl log tampering, suspicious system service creation.
- **Windows Rules (D008–D013, D016, D018):** Encoded PowerShell execution, suspicious parent-child process relationships (Office spawning cmd/pwsh), scheduled task creation, LSASS memory access, untrusted driver loading, event log clearing, protected system file modification, suspicious service binary modification.
- **Network Rules (D014, D015, D017):** Unusual outbound egress to non-standard ports, communication with known threat intelligence IOCs, single-source multi-target brute-force activity.

### 3.3 Correlation Engine Scenarios
- **Scenario C001 (Linux Compromise Kill-Chain):** Multi-stage sequence: SSH brute force $\rightarrow$ Privileged command execution $\rightarrow$ Audit log tampering on the same host within 15 minutes.
- **Scenario C002 (Windows Ransomware Precursor Chain):** Multi-stage sequence: Encoded PowerShell $\rightarrow$ Egress communication $\rightarrow$ Security event log clearing on the same host within 15 minutes.

### 3.4 Response Playbook Catalog
1. `isolate_host`: Block all non-management traffic on target host.
2. `reconnect_host`: Restore network connectivity on target host.
3. `block_ip`: Insert host firewall rule blocking inbound/outbound communication with suspicious external IP.
4. `restore_ip`: Remove firewall rule blocking specified IP.
5. `disable_user`: Lock compromised user account.
6. `enable_user`: Unlock target user account.
7. `collect_evidence`: Trigger endpoint forensic artifact collection (memory dump, process list, open sockets).

---

## 4. EXPLICIT CORE EXCLUSIONS (WHAT BLUEOPS IS NOT)

To maintain architectural focus, the following capabilities are **explicitly excluded** from the core product and will not be implemented:

1. **Not a Generic BI / Data Visualization Tool:** BlueOps will not implement customizable drag-and-drop dashboard builders or arbitrary chart generators. All UI views are strictly tailored to security triage and evidence inspection.
2. **Not an Unrestricted Remote Command Execution System:** BlueOps will never allow arbitrary bash, powershell, or shell script execution through the response agent. All endpoint actions are confined to predefined, parameter-validated playbooks.
3. **Not an Automated Malware Analysis Sandbox:** BlueOps will not include a dynamic sandbox or file detonation engine. External sandbox integrations may be added as optional enrichment providers.
4. **Not a Multi-Cloud Security Posture Manager (CSPM):** BlueOps does not scan AWS IAM policies, Azure subscriptions, or GCP buckets. Its domain is endpoint and network threat detection and response.
5. **Not a Vulnerability Scanner:** BlueOps does not perform network port scanning, CVE fuzzing, or active endpoint vulnerability probing.
6. **Not an Identity Provider:** BlueOps provides basic authentication and RBAC for its own users; it does not attempt to serve as an enterprise SSO or IdP server.

---

## 5. DEFINITION OF DONE (DoD) & ACCEPTANCE CRITERIA

A feature or bugfix is considered **DONE** and eligible for inclusion in the BlueOps Core only when all of the following criteria are satisfied:

1. **Spine Mapping:** The component directly implements or strengthens a stage in the 8-stage operational spine.
2. **Contract Conformance:** All input and output payloads conform to the schemas documented in `BLUEOPS_DATA_CONTRACTS.md`.
3. **Safe Failure Behavior:** The component implements explicit exception handling and does not fail silently or compromise system state.
4. **Test Coverage:**
   - Unit tests achieve >80% statement coverage for the new component.
   - Integration tests verify end-to-end flow with dependent services.
5. **No Regressions:** The existing automated test suite (JUnit 5, Vitest, Adversary benchmark) passes cleanly with zero failures.
6. **Documentation Updated:** Architectural documentation reflects actual code implementation without optimistic claims.
