# BlueOps Engineering Development Roadmap & Backlog

**Classification:** Engineering Task Backlog & Implementation Roadmap  
**Document ID:** BLUEOPS-ROADMAP-001  
**Version:** 1.2.0  
**Status:** Active  

---

## Task Prioritization Framework

Tasks are prioritized according to the BlueOps Master Development Directive:
- **P0 — Security and Correctness:** Critical security vulnerabilities, cryptographic integrity, parameter injection, replay risks, and concurrency hazards.
- **P1 — Core Functionality:** Bridging dynamic Sigma rule evaluation to streaming telemetry, condition algebra evaluation, alert generation, and correlation.
- **P2 — Reliability and Integration:** Comprehensive end-to-end integration tests, dead-letter queue recovery, and persistent state management.
- **P3 — Research-Enabling Capabilities:** Multi-source entity correlation, noise tolerance under missing telemetry, and quantitative evaluation benchmarks.
- **P4 — Operational Interface & Extensions:** Enhanced UX filtering, playbook editing, and advanced analytics.

---

## Active & Completed Backlog

### Phase II: Security & Reliability Remediation (P0) — [COMPLETED]

| Task ID | Component | Problem Statement | Acceptance Criteria | Target Files | Status |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **SEC-001** | `SecurityStartupValidator` | Byte-length was conflated with entropy (`length * 8`). Predictable keys passed. Profile detection only checked `"prod"`. | 1. Calculate true Shannon entropy ($H \ge 3.0$ bits/char).<br>2. Block repetitive/sequential patterns.<br>3. Inspect all production profile aliases (`prod`, `production`, `prd`, `live`).<br>4. 9 unit tests verifying rejection of predictable keys. | `SecurityStartupValidator.java`<br>`SecurityStartupValidatorTest.java` | **VERIFIED DONE** |
| **SEC-002** | `response-agent` | Nonce cache cleared at 10,000 entries. Target parameter allowed CLI option injection (`-flags`). | 1. Sliding time-window TTL eviction for nonces (`now - 65s`).<br>2. Strict regex validation rejecting leading hyphens, spaces, and format violations.<br>3. Unit tests verifying replay rejection and option injection defense. | `agent.py`<br>`drivers.py`<br>`test_agent.py` | **VERIFIED DONE** |
| **SEC-003** | `SigmaRuleRegistry` | `reloadRules()` purged map during disk traversal. Duplicate rule IDs silently overwritten. | 1. Lock-free atomic reference swap (`AtomicReference`).<br>2. Collision detection and warning logs for duplicate codes.<br>3. Multi-threaded test verifying zero-downtime concurrent queries during reload. | `SigmaRuleRegistry.java`<br>`SigmaRuleParserAndRegistryTest.java` | **VERIFIED DONE** |

---

### Phase III: Detection Engine Development (P1) — [COMPLETED]

| Task ID | Component | Problem Statement | Acceptance Criteria | Target Files | Status |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **DET-001** | Dynamic Sigma Evaluator | Sigma rules were parsed into memory but not evaluated against incoming streaming telemetry. | 1. Create `SigmaDetectionEvaluator` component.<br>2. Route normalized events by logsource product.<br>3. Connect evaluator to `DetectionEvaluationService.java`.<br>4. Generate `FindingDto` with ATT&CK metadata. | `SigmaDetectionEvaluator.java`<br>`DetectionEvaluationService.java`<br>`SigmaDetectionEvaluatorTest.java` | **VERIFIED DONE** |
| **DET-002** | Sigma Condition Algebra | Sigma conditions like `selection1 and selection2`, `selection and not filter`, or `1 of selection*` were unparsed strings. | 1. Implement recursive-descent boolean AST evaluator.<br>2. Support `and`, `or`, `not`, parentheses, and quantifier wildcards.<br>3. Support aggregation clause preprocessing.<br>4. Unit tests covering boolean tree evaluation. | `SigmaConditionEvaluator.java`<br>`SigmaConditionEvaluatorTest.java` | **VERIFIED DONE** |
| **DET-003** | Field Modifiers & Wildcards | Modifiers like `|contains`, `|endswith`, `|startswith` and wildcards were ignored. | 1. Support `|contains`, `|endswith`, `|startswith`, `|re` modifiers.<br>2. Handle normalized path slashes (`/` vs `\`).<br>3. Support Sigma multi-value list OR semantics.<br>4. Unit tests for positive and negative field matching. | `SigmaFieldMatcher.java`<br>`SigmaFieldMatcherTest.java` | **VERIFIED DONE** |

---

### Phase IV: Telemetry & Ingestion Engineering (P2) — [COMPLETED]

| Task ID | Component | Problem Statement | Acceptance Criteria | Target Files | Status |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **TEL-001** | Schema Validation Engine | `NormalizedEvent` fields required strict validation and DLQ routing under bad input. | 1. Enforce strict CES v1.0.0 boundary parsing.<br>2. Route unparseable events to DLQ with structured error metadata.<br>3. Unit tests verifying DLQ capture. | `EventNormalizationService.java`<br>`NormalizedEvent.java` | **VERIFIED DONE** |
| **TEL-002** | Dead-Letter Queue Management | DLQ events could not be purged or reprocessed via REST API. | 1. Add replay / reprocessing endpoint (`POST /api/v1/telemetry/dlq/replay`).<br>2. Add purge endpoint (`DELETE /api/v1/telemetry/dlq`).<br>3. Thread-safe DLQ synchronization. | `TelemetryController.java`<br>`EventNormalizationService.java` | **VERIFIED DONE** |

---

### Phase VII: Controlled Response Orchestration (P2 / P3) — [COMPLETED]

| Task ID | Component | Problem Statement | Acceptance Criteria | Target Files | Status |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **RSP-001** | Response Policy & Blast Radius Validator | High-impact actions lacked formal blast-radius validation and protected asset exclusion. | 1. Implement `ResponsePolicyValidator` checking character sets, protected infrastructure (127.0.0.1), and option injection.<br>2. Enforce manual approval for critical-tier assets.<br>3. Unit test verifying rejection of protected infrastructure and option injection. | `ResponsePolicyValidator.java`<br>`ResponseOrchestrationService.java`<br>`ResponsePolicyValidatorTest.java` | **VERIFIED DONE** |

---

### Phase IX & X: Applied Research & Systems Evaluation (P3) — [ACTIVE]

| Task ID | Component | Problem Statement | Acceptance Criteria | Target Files | Status |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **RES-001** | Multi-Source Entity Disambiguation | Heterogeneous logs identify entities differently (e.g. IP vs Hostname vs FQDN). | 1. Benchmark entity resolution accuracy under synthetic network and host noise.<br>2. Measure precision and recall. | `test-lab/benchmarks/entity_resolution_benchmark.js` | **PLANNED** |
| **RES-002** | Incomplete Telemetry Robustness | Sensor dropouts or network drops break strict correlation sequences. | 1. Measure detection degradation under simulated event loss (10% to 50%).<br>2. Compare with rigid SIEM baselines. | `test-lab/benchmarks/loss_tolerance_evaluator.js` | **PLANNED** |
