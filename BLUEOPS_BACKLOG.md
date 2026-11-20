# BLUEOPS ENGINEERING BACKLOG: MILESTONES & PRIORITIZED DEFECT INVENTORY

**Document Version:** 2.0.0  
**Classification:** Engineering Roadmap, Defect Backlog & Milestone Plan  
**System Document ID:** BLUEOPS-BACKLOG-2026-001  

---

## 1. MILESTONE EXECUTION ROADMAP

The development of BlueOps is sequenced into ten discrete, verifiable milestones. Progression to subsequent milestones requires complete satisfaction of the preceding milestone's acceptance criteria.

```
[M0: Reconnaissance] ──> [M1: Architectural Contracts] ──> [M2: Core Integrity Fixes (P0)]
                                                                      │
[M5: Context & Correlation] <── [M4: Investigation & Incident] <── [M3: End-to-End MV-OL (P1)]
       │
       └──> [M6: Controlled Response] ──> [M7: Reliability & Ops] ──> [M8: Branch Expansion] ──> [M9: Research]
```

| Milestone | Title | Focus & Primary Objective | Target State |
| :--- | :--- | :--- | :--- |
| **M0** | **Architectural Reconnaissance** | Complete codebase inventory, map existing components to spine, document defects, establish architectural baselines. | **Complete** |
| **M1** | **Architectural Definition & Contracts** | Formally ratify subsystem contracts, data models (CES v1.0.0), and architectural invariants across all teams. | **Complete** |
| **M2** | **Core Integrity & Security Hardening (P0)**| Resolve all critical security vulnerabilities, entropy check errors, aggregation semantic corruptions, and replay hazards. | **Complete** |
| **M3** | **Functional Detection Spine (P1)** | Execute and verify the complete functional detection spine from ingestion through finding and evidence retrieval. | **Complete** |
| **M4** | **Investigation & Incident Management** | Refine analyst triage workflows, related finding correlation, evidence provenance, and incident lifecycle state machine. | **Complete** |
| **M5** | **Context & Correlation Engine** | Canonical entity taxonomy, observation provenance, graph relationships, cross-event attack chain correlation, and incident promotion. | **Complete** |
| **M6** | **Controlled Response Orchestration & SOAR** | Policy-governed response framework, Separation of Duties, bounded simulation adapters, independent outcome verification, and host safety. | **Complete** |
| **M7** | **Operational Hardening & Reliability** | Harden OpenSearch resilience, eliminate DLQ cyclic replay loops, optimize ring buffers, and add health probes. | **Next Milestone** |
| **M8** | **Branch Expansion** | Expand Sigma catalog (Rules 19–50), integrate automated threat feeds, and build threat hunting query translator. | Expansion Gate |
| **M9** | **Research & Benchmark Defensibility** | Conduct empirical benchmarks, latency profiling under load, and evaluate novel detection hypotheses. | Evaluation Gate |

---

## 2. PRIORITIZED DEFECT & ENGINEERING BACKLOG

### Milestone M2: Core Integrity & Security Hardening (P0 Defect Resolution)

#### Task ID: BLG-M2-001 (Priority: P0 — Critical)
- **Title:** Fix Sigma Aggregation Stripping Semantic Corruption (D001, D003, D017 False Positives; D002 False Negative)
- **Subsystem:** Core C: Detection Engine (`SigmaConditionEvaluator`, `SigmaDetectionEvaluator`)
- **Evidence & Root Cause:** `SigmaConditionEvaluator.preprocessCondition()` regex-strips `| count(...) > N` and `by ...` clauses to enable single-event AST evaluation. 
  - For count rules (D001, D003, D017), stripping the count causes every single isolated authentication failure or port sweep to trigger a critical finding immediately on event 1, producing catastrophic false positives.
  - For sequence rules (D002: `selection_fail and selection_success by source.ip`), stripping `by ...` leaves `selection_fail and selection_success`. Because an individual event cannot simultaneously be both a failure and a success, D002 can never match a single event, resulting in a 100% false negative rate.
- **Remediation Specification:** 
  1. Introduce a stateful, bounded in-memory sliding-window event aggregation buffer (`AggregationStateStore`) keyed by the grouped entity (e.g. `source.ip`, `user.name`).
  2. For count rules, evaluate base selections on incoming events, increment entity window counters, and fire findings only when the count exceeds the threshold within the sliding time window (e.g. 5 failures in 300 seconds).
  3. For sequence rules, track state transitions across the entity window.
- **Acceptance Criteria:** A single SSH failure generates 0 findings; exactly 5 SSH failures within 5 minutes trigger D001; 1 failure followed by 1 success triggers D002.

#### Task ID: BLG-M2-002 (Priority: P0 — Critical)
- **Title:** Remediate Multi-Worker Replay & Race Condition Vulnerability in Response Agent Nonce Cache
- **Subsystem:** Core G: Response Orchestration (`response-agent/src/agent.py`)
- **Evidence & Root Cause:** In `agent.py`, `PROCESSED_NONCES` is a standard Python in-memory `dict` with no process lock or shared memory. In multi-worker deployments (e.g., Gunicorn/Uvicorn with 4 workers), memory is isolated per worker process. An attacker capturing a valid signed payload within the 60-second validity window can replay the payload against a different worker process. Additionally, concurrent requests to the same worker can race between the check and assignment.
- **Remediation Specification:**
  1. Replace the plain dictionary with a file-locked SQLite cache (`sqlite3` with `WAL` mode and transactions) or a thread-safe synchronized cache with an atomic test-and-set operation.
  2. Impose a strict maximum capacity limit (e.g. 50,000 entries) with immediate LRU eviction to prevent unbounded memory growth under request floods.
- **Acceptance Criteria:** Automated test script fires 100 concurrent identical requests with the same nonce across multiple processes; exactly 1 succeeds (HTTP 200) and 99 are rejected with HTTP 409 Conflict.

#### Task ID: BLG-M2-003 (Priority: P0 — Critical)
- **Title:** Fix SecurityStartupValidator Profile Fail-Open Defect & Cryptographic Keyspace Fallacy
- **Subsystem:** Core H: Platform Operations (`SecurityStartupValidator.java`)
- **Evidence & Root Cause:**
  1. *Profile Fail-Open:* In `SecurityStartupValidator.isProductionEnvironment()`, if `spring.profiles.active` is not explicitly set (or defaults to `dev`), weak hardcoded secrets boot successfully without throwing an exception.
  2. *Entropy Fallacy:* The Shannon entropy calculation $H = -\sum P(x) \log_2 P(x)$ measures character distribution across the secret string, NOT cryptographic entropy. Predictable sequences like `"abcdefghijklmnopqrstuvwxyz012345"` pass validation despite having near-zero keyspace randomness.
- **Remediation Specification:**
  1. Refactor startup validator to enforce a minimum secret length (>= 32 bytes / 256 bits for HMAC-SHA256).
  2. Maintain a blacklist of known default and dictionary secrets (e.g., `"404E6352..."`, `"b7c938d1..."`, `"password123"`).
  3. Reject sequential or repetitive character sequences ($H_{min} \ge 3.8$ bits/byte AND zero dictionary matches).
  4. Ensure fail-closed behavior: if environment variables `JWT_SECRET` or `RESPONSE_AGENT_SECRET` are unset in production, terminate JVM startup immediately.
- **Acceptance Criteria:** Server refuses to boot with known defaults or sequential strings; boots successfully with `java.security.SecureRandom` generated keys.

#### Task ID: BLG-M2-004 (Priority: P1 — High)
- **Title:** Close Policy Validation Bypass on Action Rollback and Uninventoried Asset Targets
- **Subsystem:** Core G: Response Orchestration (`ResponseOrchestrationService.java`)
- **Evidence & Root Cause:**
  1. `policyValidator.validateRequest()` is invoked only inside `requestAction()`. If `rollbackAction()` or direct `executeAction()` is called, policy bounds are bypassed entirely.
  2. In `requestAction()`, if a target IP/hostname does not match an existing `Asset` record in PostgreSQL, `targetAsset` is `null`. The check `targetAsset.getCriticality().equals("CRITICAL")` evaluates to false, allowing auto-approval of uninventoried IP addresses.
- **Remediation Specification:**
  1. Move policy validation into a centralized pre-execution interceptor invoked before ANY execution (request, approve, or rollback).
  2. If `targetAsset == null`, enforce a default conservative policy: treat uninventoried targets as requiring manual approval if the playbook is destructive.
- **Acceptance Criteria:** Calling `rollbackAction()` on a protected subnet target throws `InvalidActionException`; uninventoried host targets require manual approval.

#### Task ID: BLG-M2-005 (Priority: P1 — High)
- **Title:** Eliminate Cyclic Dead-Letter Queue (DLQ) Infinite Replay Loop
- **Subsystem:** Core B: Event Processing (`TelemetryController.java`, `EventNormalizationService.java`)
- **Evidence & Root Cause:** In `POST /api/v1/telemetry/dlq/replay`, the DLQ is cleared and events are passed back to `normalize()`. If an event has a permanent structural or type error (e.g. malformed JSON or unparseable timestamp), `normalize()` throws an exception and immediately re-appends the event back to the DLQ. Repeated replay calls cause CPU spin and log thrashing.
- **Remediation Specification:**
  1. Add a `replay_count` integer to DLQ metadata.
  2. If `replay_count >= 3`, classify the payload as a "poison pill" and move it to an archived dead-letter store (`dlq_poison_pills`), preventing re-ingestion.
- **Acceptance Criteria:** Poison-pill events are evicted after 3 failed replay attempts with clear diagnostic logs.

---

### Milestone M3: Functional Event Lifecycle (P1 End-to-End Capabilities)

#### Task ID: BLG-M3-001 (Priority: P1)
- **Title:** Automated End-to-End MV-OL Verification Harness
- **Subsystem:** Cross-Cutting / Test-Lab
- **Description:** Implement an automated integration test that executes the full 16-step operational lifecycle on a clean test instance:
  1. Ingest benign Sysmon event $\rightarrow$ Verify zero findings generated.
  2. Ingest adversary attack event (D008) $\rightarrow$ Verify finding generated, incident synthesized, policy checked, and simulated response executed.
- **Acceptance Criteria:** Test executes in <5 seconds in CI with 100% assertions passing.

#### Task ID: BLG-M3-002 (Priority: P1)
- **Title:** Preserve Raw Event Provenance in OpenSearch Finding Documents
- **Subsystem:** Core E: Investigation (`OpenSearchFindingAdapter.java`)
- **Description:** Ensure that the generated `FindingDto` encapsulates the complete raw event ID and original log snippet in `finding.details.evidence_raw`, enabling one-click drill-down in the investigation workspace.
- **Acceptance Criteria:** Finding detail API returns exact unparsed original telemetry log string.

---

### Milestone M4: Investigation & Incident Management (P2 Strengthening)

#### Task ID: BLG-M4-001 (Priority: P2)
- **Title:** Parent-Child Process Tree Reconstruction in SOC UI
- **Subsystem:** Core E: Investigation (`frontend/src/pages/InvestigationWorkspacePage.tsx`)
- **Description:** Parse `ProcessId`, `ParentProcessId`, `Image`, and `ParentImage` from Windows Sysmon and Linux auditd events to render an interactive hierarchical tree of process execution.
- **Acceptance Criteria:** UI renders visual tree branching from `cmd.exe` $\rightarrow$ `powershell.exe` with command line arguments and timestamps.

#### Task ID: BLG-M4-002 (Priority: P2)
- **Title:** Incident State Machine Guardrails & Transition History
- **Subsystem:** Core F: Incident Management (`IncidentService.java`)
- **Description:** Enforce strict allowable state transitions:
  - `NEW` $\rightarrow$ `ASSIGNED`
  - `ASSIGNED` $\rightarrow$ `IN_PROGRESS`
  - `IN_PROGRESS` $\rightarrow$ `CONTAINED`
  - `CONTAINED` $\rightarrow$ `CLOSED`
  - Direct jump from `NEW` to `CLOSED` without containment must be rejected unless marked as `FALSE_POSITIVE`.
- **Acceptance Criteria:** Illegal state transitions throw `InvalidActionException` with explanatory error messages.

---

### Milestone M5: Context & Correlation Engine (P2 Strengthening)

#### Task ID: BLG-M5-001 (Priority: P2)
- **Title:** Persistent Sliding-Window Correlation State Store
- **Subsystem:** Core F: Incident Management (`CorrelationEngine.java`)
- **Description:** Transition `CorrelationEngine` from querying transient in-memory findings to reading a sliding 15-minute time-window table in PostgreSQL, ensuring correlation state survives backend restarts.
- **Acceptance Criteria:** Backend restart mid-attack-chain does not lose previous stages; completing the final stage correctly triggers the correlation incident.

---

### Milestone M6: Controlled Response & Verification (P3 Expansion)

#### Task ID: BLG-M6-001 (Priority: P3)
- **Title:** Implement Production Host Isolation & Forensic Collection Drivers
- **Subsystem:** Core G: Response Orchestration (`response-agent/src/drivers.py`)
- **Description:** Replace stubs in `LinuxDriver` and `WindowsDriver` with actual OS commands:
  - Linux `isolate_host`: Configure `iptables` drop rules with explicit SSH management exception.
  - Windows `isolate_host`: Configure `netsh advfirewall` stateful isolation.
  - `collect_evidence`: Execute secure process memory dump to encrypted local staging directory.
- **Acceptance Criteria:** Automated test in virtual machine confirms target network dropped while maintaining response agent control channel.

---

## 3. DEFECT AUDIT SUMMARY TABLE

| Defect ID | Component | Severity | Description | Milestone | Status |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **DEF-001** | `SigmaConditionEvaluator` / `SigmaAggregationEngine` | **CRITICAL** | Aggregation stripping causes false positive flood on single failures (D001, D003, D017) and 100% false negative on D002. | M2 | **RESOLVED & VERIFIED** |
| **DEF-002** | `response-agent/src/agent.py` | **CRITICAL** | Nonce cache in-memory dict lacks process locks and isolation in multi-worker WSGI deployments, permitting replay attacks. | M2 | **RESOLVED & VERIFIED** |
| **DEF-003** | `SecurityStartupValidator` | **CRITICAL** | Profile check fails open when profile unset; Shannon character entropy mistreats predictable sequential strings as high entropy. | M2 | **RESOLVED & VERIFIED** |
| **DEF-004** | `ResponseOrchestrationService`| **HIGH** | Policy boundary validation bypassed during action rollback and for uninventoried IP targets. | M2 | **RESOLVED & VERIFIED** |
| **DEF-005** | `TelemetryController` / `EventNormalizationService` | **HIGH** | DLQ replay endpoint triggers infinite cyclic loop when re-normalizing unfixable poison-pill payloads. | M2 | **RESOLVED & VERIFIED** |
| **DEF-006** | `CorrelationEngine` | **MEDIUM** | In-memory finding adapter drops correlation state on JVM restart. | M5 | Backlog |
| **DEF-007** | `drivers.py` | **LOW** | Host isolation and evidence collection methods are simulation-only stubs in live mode. | M6 | Backlog |
