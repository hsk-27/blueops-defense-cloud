# BlueOps — Defect & Remediation Register

This register documents all security, architectural, and data engineering defects identified during the deep autonomous audit, their root causes, remediations, and verification results.

---

### DEF-001: Missing Audit Trail on Critical Platform Operations
- **Severity:** HIGH  
- **Affected Subsystems:** `ResponseOrchestrationService.java`, `IncidentService.java`, `AssetService.java`, `DetectionRuleService.java`  
- **Root Cause:** While `AuditService.recordEvent(...)` and the `audit_logs` table were implemented, critical mutation operations (approving response actions, updating incident status, re-assigning incidents, creating assets, disabling detection rules) failed to invoke the audit recording mechanism.  
- **Remediation:** Integrated `auditService.recordEvent(...)` into:
  - `IncidentService`: `createIncident`, `updateStatus`, `reopenIncident`, `assignIncident`.
  - `ResponseOrchestrationService`: `requestAction`, `approveAction`, `rejectAction`, `rollbackAction`.
  - `AssetService`: `createAsset`, `updateAsset`, `deleteAsset`.
  - `DetectionRuleService`: `updateRuleStatus`.
- **Verification Status:** VERIFIED. Audit records are consistently created for all mutation workflows with user identity and JSON metadata.

---

### DEF-002: Lack of Authentication Rate Limiting & Account Lockout
- **Severity:** HIGH  
- **Affected Subsystems:** `AuthService.java`, `AuthController.java`  
- **Root Cause:** The `/api/v1/auth/login` endpoint had no mechanism to detect or mitigate high-frequency credential stuffing or password brute-force attacks.  
- **Remediation:**
  - Implemented `LoginRateLimiter.java` using a thread-safe sliding window algorithm (`ConcurrentHashMap`).
  - Configured maximum 5 consecutive failed login attempts per username or IP within a 15-minute window.
  - Exceeding the threshold triggers an automatic 15-minute lockout returning HTTP 429 (`TOO_MANY_REQUESTS`).
  - Successful authentication immediately clears failure history.
- **Verification Status:** VERIFIED via `LoginRateLimiterTest.java` (2/2 passing tests verifying lockout after 5 attempts and reset on success).

---

### DEF-003: Detection Rule Inconsistencies & Missing Rule Implementations
- **Severity:** HIGH  
- **Affected Subsystems:** `DetectionEvaluationService.java`, `V2__seed_initial_data.sql`, `detection-rules/sigma/`  
- **Root Cause:**
  - Rule `D012` in code was mapped to "Windows Event Log Clearing", but in Sigma/SQL it is "Unexpected Driver Loading".
  - Rule `D013` in code was mapped to "SC.exe Service Creation", but in Sigma/SQL it is "Security Event Log Clearing".
  - Rule `D016` in code only checked registry run keys, while in Sigma it is "Protected-File Modification" (specifically `hosts` files).
  - Rule `D018` in code only checked `svchost.exe` masquerading, but in Sigma it covers administrative service execution (`sc create`).
  - Rules `D007` (Linux systemd unit creation) and `D017` (repeated authentication failures across sources) were completely absent from `DetectionEvaluationService.java`.
- **Remediation:**
  - Aligned all rule codes D001 through D018 with `V2__seed_initial_data.sql` and Sigma YAML definitions.
  - Implemented detection for `D007` (systemd unit creation in `/etc/systemd/system`).
  - Implemented detection for `D012` (unexpected kernel driver loading, `.sys` outside System32 drivers, `driver_loaded` action).
  - Implemented detection for `D013` (security event log clearing via `wevtutil cl` or `Clear-EventLog`).
  - Implemented detection for `D016` (protected file modification targeting `/etc/hosts` or `drivers\etc\hosts`).
  - Implemented detection for `D017` (cross-platform authentication failure aggregation).
  - Aligned `D018` to detect administrative service creation (`sc create`) and service host masquerading.
- **Verification Status:** VERIFIED via `TelemetryNormalizationAndDetectionTest.java` (tests for D007, D012, D013, D016, D017, and D018 all passing).

---

### DEF-004: Permissive Response Agent Execution Boundary & Unsanitized Target Inputs
- **Severity:** HIGH  
- **Affected Subsystems:** `response-agent/src/agent.py`, `response-agent/tests/test_agent.py`  
- **Root Cause:**
  - `agent.py` did not check if the incoming action or playbook mapped to an authorized action in `ALLOWLISTED_ACTIONS`.
  - The `target` parameter was not checked for shell injection characters (`;&|`$><\r\n`).
  - The secret key was hardcoded rather than falling back from `os.environ.get("RESPONSE_AGENT_SECRET")`.
- **Remediation:**
  - Updated `agent.py` to resolve `RESPONSE_AGENT_SECRET` from environment variables.
  - Added strict validation against `ALLOWLISTED_ACTIONS` and `PLAYBOOK_TO_ACTION`, rejecting unauthorized actions with HTTP 400 (`REJECTED_UNAUTHORIZED_ACTION`).
  - Added regex sanitization rejecting shell metacharacters in `target` with HTTP 400 (`REJECTED_INVALID_PARAMETER`).
  - Added comprehensive pytest test cases in `test_agent.py` for expired timestamps, unauthorized actions, and command injection attempts.
- **Verification Status:** VERIFIED via `deceptive_attack_suite.js` (5/5 boundary security tests passing).

---

### DEF-005: Unbounded Database Memory Consumption in ReportingService
- **Severity:** MEDIUM  
- **Affected Subsystems:** `ReportingService.java`, `IncidentRepository.java`  
- **Root Cause:** `ReportingService.getSocOverviewMetrics()` called `incidentRepository.findAll().stream()` multiple times to compute distinct affected assets, average containment time, and recent incidents, loading the entire incidents table into memory.  
- **Remediation:**
  - Added database-level query methods to `IncidentRepository`:
    - `@Query("SELECT COUNT(DISTINCT i.primaryAsset.id) FROM Incident i WHERE i.primaryAsset IS NOT NULL AND i.status NOT IN ('RESOLVED', 'FALSE_POSITIVE')") long countAssetsWithActiveIncidents();`
    - `List<Incident> findTop5ByOrderByCreatedAtDesc();`
    - `List<Incident> findByContainedAtIsNotNullAndCreatedAtIsNotNull();`
  - Refactored `ReportingService.java` to use these dedicated database queries.
- **Verification Status:** VERIFIED via offline Maven test compilation and execution.

---

### DEF-006: Potential Cyclic Serialization in JPA Entities
- **Severity:** MEDIUM  
- **Affected Subsystems:** `IncidentFinding.java`, `IncidentNote.java`, `IncidentStatusHistory.java`  
- **Root Cause:** The `@ManyToOne(fetch = FetchType.LAZY)` reference to `Incident` in child entities lacked `@JsonIgnore`, risking infinite recursion or lazy-loading exceptions during JSON serialization.  
- **Remediation:** Added `@JsonIgnore` to the `incident` property across `IncidentFinding`, `IncidentNote`, and `IncidentStatusHistory`.  
- **Verification Status:** VERIFIED via backend compilation and JSON serialization tests.

---

### DEF-007: OpenSearch Remote Timestamp Loss in Finding Adapter
- **Severity:** MEDIUM  
- **Affected Subsystems:** `OpenSearchFindingAdapter.java`  
- **Root Cause:** In `parseSearchHits()`, line 114 unconditionally set `dto.setTimestamp(Instant.now())`, destroying the original detection timestamp of remote OpenSearch findings.  
- **Remediation:** Updated `parseSearchHits()` to inspect `@timestamp` and `timestamp` fields from OpenSearch `_source`, safely parsing ISO strings or numeric epoch timestamps before falling back to `Instant.now()`.  
- **Verification Status:** VERIFIED via `TelemetryNormalizationAndDetectionTest.java`.

---

### DEF-008: Non-Dynamic Benchmark Simulation Driver
- **Severity:** MEDIUM  
- **Affected Subsystems:** `test-lab/run_simulations.js`  
- **Root Cause:** `run_simulations.js` computed metrics based on a static JSON array with pre-populated `tp: true, fp: 0` values rather than dynamically processing telemetry events through detection logic.  
- **Remediation:** Rebuilt `test-lab/run_simulations.js` into an empirical research benchmark engine:
  - Dynamically runs 10 Atomic Red Team adversary telemetry payloads.
  - Dynamically runs 50 realistic benign enterprise baseline telemetry streams.
  - Dynamically matches each event against BlueOps Sigma rules and Threat Intel IOCs.
  - Computes dynamic MTTD latencies, empirical TP/FP/TN/FN counts, Precision, Recall, Specificity, and FPR.
  - Exports validated findings to `test-lab/results/benchmark_report.json`.
- **Verification Status:** VERIFIED via `node test-lab/run_simulations.js` (10/10 TP, 50/50 TN, 0 FP, 0 FN).

---

### DEF-009: Missing Filter-Chain Defense-in-Depth for Administrative Response Actions
- **Severity:** MEDIUM  
- **Affected Subsystems:** `SecurityConfig.java`, `ResponseController.java`  
- **Root Cause:** While `@PreAuthorize("hasRole('ADMIN')")` protected response actions at the method level, `SecurityConfig.java` did not explicitly list `/api/v1/response/actions/*/execute` and `/api/v1/response/actions/*/rollback` in its HTTP security filter chain rules.  
- **Remediation:** Explicitly registered `.requestMatchers(HttpMethod.POST, "/api/v1/response/actions/*/execute", "/api/v1/response/actions/*/rollback").hasRole("ADMIN")` in `SecurityConfig.java`.  
- **Verification Status:** VERIFIED via `SecurityConfig.java` audit and compilation.

---

### DEF-010: Outdated Sigma Rule Reference in Adversary Suite
- **Severity:** LOW  
- **Affected Subsystems:** `test-lab/adversary-simulation/deceptive_attack_suite.js`  
- **Root Cause:** `ATK-004` (Event Log Clearing) expected rule `D012` instead of the corrected canonical code `D013`.  
- **Remediation:** Updated `deceptive_attack_suite.js` to expect `D013` with `CRITICAL` severity.  
- **Verification Status:** VERIFIED via `node test-lab/adversary-simulation/deceptive_attack_suite.js` (8/8 attacks passing).
