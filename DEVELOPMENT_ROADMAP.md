# BlueOps Engineering Development Roadmap & Backlog

**Classification:** Engineering Task Backlog & Implementation Roadmap  
**Document ID:** BLUEOPS-ROADMAP-001  
**Version:** 1.0.0  
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

## Active Backlog

### Phase II: Security & Reliability Remediation (P0)

| Task ID | Component | Problem Statement | Acceptance Criteria | Target Files |
| :--- | :--- | :--- | :--- | :--- |
| **SEC-001** | `SecurityStartupValidator` | Byte-length is incorrectly equated with entropy (`jwtBytes.length * 8`). Predictable keys (e.g. 32 identical characters) pass. Profile detection only checks `"prod"`, missing `"production"` or `"prd"`. | 1. Calculate true Shannon entropy ($H \ge 3.8$ bits/byte).<br>2. Block repetitive/sequential patterns.<br>3. Inspect all production profile aliases (`prod`, `production`, `prd`, `live`).<br>4. Unit tests verifying rejection of predictable keys. | `backend/.../security/SecurityStartupValidator.java`<br>`backend/.../security/SecurityStartupValidatorTest.java` |
| **SEC-002** | `response-agent` | 1. Nonce cache calls `.clear()` at 10,000 entries, allowing replay attacks during active validity window.<br>2. Target parameter allows CLI option injection (leading `-` or spaces). | 1. Implement sliding time-window TTL eviction for nonces.<br>2. Enforce strict regex validation rejecting leading hyphens, spaces, and invalid CIDR/POSIX formats.<br>3. Unit tests verifying replay rejection and option injection defense. | `response-agent/src/agent.py`<br>`response-agent/src/drivers.py`<br>`response-agent/tests/test_agent.py` |
| **SEC-003** | `SigmaRuleRegistry` | 1. `reloadRules()` purges in-memory map before disk scan, creating a concurrency null-pointer window.<br>2. Duplicate rule identifiers silently overwrite existing rules without audit warnings. | 1. Use atomic reference replacement (`AtomicReference<Map<String, SigmaRuleDefinition>>`).<br>2. Reject or log explicit collision warnings for duplicate rule IDs.<br>3. Unit test verifying zero-downtime concurrent queries during reload. | `backend/.../detections/SigmaRuleRegistry.java`<br>`backend/.../detections/SigmaRuleParserAndRegistryTest.java` |

---

### Phase III: Detection Engine Development (P1)

| Task ID | Component | Problem Statement | Acceptance Criteria | Target Files |
| :--- | :--- | :--- | :--- | :--- |
| **DET-001** | Dynamic Sigma Evaluator | Sigma rules are parsed into memory but `DetectionEvaluationService` does not execute them against streaming telemetry. | 1. Create `SigmaDetectionEvaluator` component.<br>2. Match `NormalizedEvent` fields against Sigma selections.<br>3. Integrate evaluator into `DetectionEvaluationService.java`.<br>4. Generate findings with Sigma rule ID and title. | `backend/.../detections/SigmaDetectionEvaluator.java`<br>`backend/.../telemetry/DetectionEvaluationService.java` |
| **DET-002** | Sigma Condition Algebra | Sigma conditions like `selection1 and selection2`, `selection and not filter`, or `1 of selection*` are unparsed strings. | 1. Implement condition expression tokenizer and boolean AST evaluator.<br>2. Support `and`, `or`, `not`, parentheses, and selection references.<br>3. Explicitly reject or log unsupported aggregation syntax without crashing.<br>4. Unit tests covering complex boolean logic. | `backend/.../detections/SigmaConditionEvaluator.java`<br>`backend/.../detections/SigmaConditionEvaluatorTest.java` |
| **DET-003** | Field Modifiers & Wildcards | Sigma modifiers like `|contains`, `|endswith`, `|startswith` and wildcards (`*`, `?`) are ignored or treated as literals. | 1. Support `|contains`, `|endswith`, `|startswith`, `|re` modifiers.<br>2. Translate Sigma glob wildcards (`*powershell*`) to case-insensitive regex or substrings.<br>3. Support multi-value lists (OR semantics).<br>4. Unit tests for positive and negative field matches. | `backend/.../detections/SigmaFieldMatcher.java`<br>`backend/.../detections/SigmaFieldMatcherTest.java` |

---

### Phase IV: Telemetry & Ingestion Engineering (P2)

| Task ID | Component | Problem Statement | Acceptance Criteria | Target Files |
| :--- | :--- | :--- | :--- | :--- |
| **TEL-001** | Schema Validation Engine | `NormalizedEvent` accepts fields without strict schema boundary validation. | 1. Enforce strict CES v1.0.0 schema constraints.<br>2. Route unparseable or schema-violating events to the DLQ with structured error metadata.<br>3. Unit tests verifying DLQ routing. | `backend/.../telemetry/EventNormalizationService.java`<br>`backend/.../telemetry/NormalizedEvent.java` |
| **TEL-002** | Dead-Letter Queue Management | DLQ events cannot be reprocessed or exported via API. | 1. Add replay / reprocessing endpoint for DLQ events.<br>2. Expose clearable DLQ buffer for administrators.<br>3. Unit tests for DLQ lifecycle. | `backend/.../telemetry/TelemetryController.java`<br>`backend/.../telemetry/TelemetryService.java` |

---

### Phase V & VII: Correlation & Response Orchestration (P2 / P3)

| Task ID | Component | Problem Statement | Acceptance Criteria | Target Files |
| :--- | :--- | :--- | :--- | :--- |
| **COR-001** | Dynamic Correlation Pipeline | Correlation scenarios are currently hardcoded; detections from dynamic Sigma rules need automated aggregation. | 1. Map dynamic Sigma detection findings into correlation sliding windows by `host.hostname` and `user.username`.<br>2. Synthesize multi-stage incidents with attack progression timelines.<br>3. Comprehensive integration tests for kill-chain synthesis. | `backend/.../correlation/CorrelationService.java`<br>`backend/.../incidents/IncidentService.java` |
| **RSP-001** | Response Policy & Approval | High-impact response actions require automated policy validation and two-person approval controls. | 1. Implement `ResponsePolicyValidator` checking action impact level and asset criticality.<br>2. Require explicit approval token for actions with `CRITICAL` or `HIGH` impact.<br>3. Audit trail for every proposal, approval, and execution attempt. | `backend/.../response/ResponseActionService.java`<br>`backend/.../response/ResponsePolicyValidator.java` |

---

### Phase IX & X: Empirical Evaluation & Applied Research (P3)

| Task ID | Component | Problem Statement | Acceptance Criteria | Target Files |
| :--- | :--- | :--- | :--- | :--- |
| **RES-001** | Multi-Source Entity Disambiguation | Heterogeneous logs (Sysmon vs auditd vs Suricata) identify entities differently (e.g. IP vs Hostname vs FQDN). | 1. Implement cross-source Entity Graph Resolver.<br>2. Link network connections to endpoint processes.<br>3. Benchmark entity resolution accuracy under synthetic noise. | `backend/.../correlation/EntityResolver.java`<br>`test-lab/benchmarks/entity_resolution_benchmark.js` |
| **RES-002** | Incomplete Telemetry Robustness | Network log drops or sensor latency break strict correlation sequences. | 1. Probabilistic or fuzzy time-window correlation under simulated packet/event loss (10% to 50%).<br>2. Measure precision and recall vs traditional rigid SIEM rules. | `test-lab/benchmarks/loss_tolerance_evaluator.js` |
