# BLUEOPS ARCHITECTURAL DECISION RECORDS (ADR)

**Document Version:** 2.0.0  
**Classification:** Architectural Governance & Decision History  
**System Document ID:** BLUEOPS-ADR-2026-001  

---

## 1. ADR INDEX

| ADR ID | Title | Status | Date Ratified | Impact Area |
| :--- | :--- | :--- | :--- | :--- |
| **ADR-001** | Selection of Modular Monolith Backend over Distributed Microservices | **Accepted** | 2026-11-01 | Architecture / Deployment |
| **ADR-002** | Dual Data Store Strategy: PostgreSQL Relational + OpenSearch Search | **Accepted** | 2026-11-02 | Persistence / Reliability |
| **ADR-003** | In-Process Sigma Rule Stream Evaluator with AST Parser | **Accepted** | 2026-11-03 | Detection Engine |
| **ADR-004** | Decoupled Response Daemon with HMAC-SHA256 & Anti-Replay Nonce Cache | **Accepted** | 2026-11-04 | SOAR / Host Security |
| **ADR-005** | Bounded In-Memory Ring Buffer & DLQ vs External Message Broker | **Accepted** | 2026-11-05 | Ingestion / Buffering |
| **ADR-006** | Pre-Execution Policy Validator & Simulation Defaults for Defensive Actions | **Accepted** | 2026-11-06 | Safety Governance |
| **ADR-007** | Cryptographic Startup Entropy Verification Protocol | **Accepted** | 2026-11-07 | Application Security |
| **ADR-008** | Stateful Sliding-Window Aggregation & Sequence Engine for Sigma Rules | **Accepted** | 2026-11-20 | Detection Engine |
| **ADR-009** | Dead-Letter Queue Poison Pill Quarantine Protocol | **Accepted** | 2026-11-20 | Ingestion Reliability |

---

## 2. DETAILED ARCHITECTURAL DECISION RECORDS

### ADR-001: Selection of Modular Monolith Backend over Distributed Microservices

#### Context & Problem Statement
Cybersecurity platforms often suffer from premature microservice decomposition. Splitting Ingestion, Normalization, Detection, Correlation, Incident Management, and Response into distinct containerized services introduces high network serialization latency, distributed transaction complexity, network partition failure modes, and substantial operational overhead (requiring Kubernetes, service meshes, and distributed tracing).

#### Decision
We explicitly reject a multi-service distributed architecture for the BlueOps core. The platform will be built and maintained as a **Modular Monolith** within a single Java/Spring Boot application context (`blueops-backend`).

#### Consequences & Trade-offs
- **Positive:** Nanosecond in-memory event passing between normalization, detection, and correlation; zero distributed transactions; unified deployment via a single JVM; trivial local debugging and end-to-end integration testing.
- **Negative:** Horizontal scaling of ingestion alone scales the entire application.
- **Mitigation:** Modular package structure (`com.blueops.<subsystem>`) enforces strict package isolation. If ingestion ever requires dedicated scaling, the `com.blueops.telemetry` package can be extracted into an independent forwarder with zero domain code modifications.

---

### ADR-002: Dual Data Store Strategy (PostgreSQL + OpenSearch)

#### Context & Problem Statement
Security platforms must handle two fundamentally incompatible data access patterns:
1. High-volume, unstructured, semi-structured append-only log streams requiring full-text search, regex lookups, and fast time-series aggregation.
2. Highly structured, relational, transactional entities (incidents, user accounts, audit trails, playbooks) requiring ACID guarantees, referential integrity, and strict state transitions.

Attempting to force log telemetry into relational tables degrades query performance; attempting to manage incident states or RBAC within OpenSearch introduces eventual-consistency race conditions.

#### Decision
We adopt a strict **Dual-Store Ownership Model**:
- **PostgreSQL 16:** Authoritative system of record for Incidents, Users, RBAC, Assets, Response Playbooks, and Audit Logs. Managed via Flyway migrations.
- **OpenSearch 2.13:** Inverted-index document store for Normalized Telemetry Events and Security Findings.
- **Resilience Guardrail:** In the event of OpenSearch cluster failure, the `OpenSearchFindingAdapter` automatically falls back to an in-process thread-safe concurrent store, allowing detection, correlation, and incident management to proceed without downtime.

---

### ADR-003: In-Process Sigma Rule Stream Evaluator with AST Parser

#### Context & Problem Statement
Standard detection engineering either translates Sigma rules into database search queries (e.g. running continuous Elasticsearch queries every 60 seconds) or requires external heavy execution daemons (like ElastAlert). Periodic querying introduces detection latency (up to the query interval) and incurs heavy I/O load on the search cluster.

#### Decision
BlueOps implements a **Custom In-Process Sigma Stream Evaluator**:
1. SnakeYAML parses standard Sigma YAML rule definitions into a strongly typed `SigmaRuleDefinition`.
2. A thread-safe `SigmaRuleRegistry` indexes active rules and permits lock-free atomic hot-reloading via `AtomicReference`.
3. A recursive Boolean parser compiles rule condition strings into an in-memory Abstract Syntax Tree (`SigmaConditionEvaluator`).
4. As events arrive at `/api/v1/telemetry/ingest`, they are evaluated against the ASTs in real time without touching the disk or database.

#### Consequences & Mitigations
- Single-event field matching operates at sub-millisecond speeds.
- Multi-event aggregations (`| count() > N by entity`) cannot be evaluated on single events. Milestone M2 introduces a dedicated sliding-window state store (`AggregationStateStore`) to handle counts without stripping syntax.

---

### ADR-004: Decoupled Out-of-Process Response Agent with HMAC-SHA256

#### Context & Problem Statement
Executing defensive containment actions (firewall rules, account freezing) requires root/Administrator OS privileges. Running the entire BlueOps platform as root or giving the web server direct SSH access to target machines is an unacceptably high security liability.

#### Decision
Response execution is decoupled into a dedicated, minimal Python daemon (`response-agent`) deployed on managed hosts.
1. The backend authenticates to the agent via application-layer **HMAC-SHA256 signatures** calculated over the HTTP method, URI, timestamp, nonce, and request body.
2. The agent enforces a strict 60-second validity window and caches nonces in a sliding TTL window to defeat replay attacks.
3. The agent exposes only an immutable catalogue of verified playbooks (`block_ip`, `isolate_host`, `disable_user`); arbitrary shell commands are rejected by design.

---

### ADR-005: Bounded In-Memory Ring Buffer & Synchronized DLQ

#### Context & Problem Statement
Enterprise message queues (Kafka, RabbitMQ) provide durability but impose heavy operational complexity and resource consumption in dev, evaluation, and edge deployments. We need a lightweight event buffering solution that protects the system from memory exhaustion while preventing event loss.

#### Decision
BlueOps Core implements a **Bounded Concurrent In-Memory Ring Buffer** (1,000 events) and a **Synchronized Dead-Letter Queue** (500 events).
- Normalization exceptions route the original raw payload to the DLQ with the stack trace.
- The DLQ exposes REST endpoints for inspection, clearing, and replay (`POST /api/v1/telemetry/dlq/replay`).
- Poison-pill tracking (M2) prevents cyclic replay loops.

---

### ADR-006: Pre-Execution Policy Validator and Simulation Defaults

#### Context & Problem Statement
Automated SOAR playbooks pose severe operational risks: a buggy rule or an adversary spoofing an IP address could cause an automated script to block the default gateway, isolate domain controllers, or freeze all administrator accounts.

#### Decision
1. **Simulation Default:** The system default is `simulation-mode: true`. Actions are simulated and validated against regex drivers without altering the host OS unless explicitly approved.
2. **Policy Boundary Engine:** `ResponsePolicyValidator` acts as an independent firewall before execution, unconditionally rejecting actions that target:
   - Loopback (`127.0.0.1`, `::1`, `localhost`)
   - Default network gateways and controller IP addresses
   - Assets marked with `criticality: CRITICAL` unless manually authorized by an administrator.

---

### ADR-007: Cryptographic Startup Entropy Verification Protocol

#### Context & Problem Statement
Deployments often leave default placeholder secrets in configuration files, creating critical vulnerabilities (e.g., hardcoded JWT secrets allow adversaries to forge administrative tokens). Simple length checks are insufficient because predictable strings (e.g. `123456...`) satisfy length requirements.

#### Decision
The `SecurityStartupValidator` executes at Spring context initialization:
1. Rejects known default development secrets (hardcoded blacklist).
2. Calculates Shannon character entropy and requires $H \ge 3.8$ bits/byte.
3. Enforces a minimum length of 32 bytes (256 bits).
4. Terminate JVM startup with `IllegalStateException` if production profiles are active with insecure secrets.

---

### ADR-008: Stateful Sliding-Window Aggregation & Sequence Engine for Sigma Rules

#### Context & Problem Statement
Sigma detection rules frequently incorporate multi-event count aggregations (e.g. `| count(event.id) by source.ip > 5` for SSH brute force) or sequence correlations (e.g. `selection_fail and selection_success by source.ip`). Naive condition evaluators strip pipeline clauses (`| ...`), causing rules to trigger prematurely on a single event (generating false positive storms) or fail to match sequence pairs.

#### Decision
We introduce `SigmaAggregationEngine` in `com.blueops.detections.sigma`:
1. Differentiates single-event rules from pipeline aggregations and sequence correlations.
2. Maintains thread-safe sliding-window event timestamp queues (`countWindows`) keyed by rule code and entity identifier (source IP, username, or asset ID).
3. Automatically prunes events older than the rule's defined `timeframe` (defaulting to 300s).
4. Fired findings occur only when the entity count exceeds the declared threshold within the window.
5. Tracks intermediate states for sequence rules, resetting upon sequence completion to prevent alert flapping.

---

### ADR-009: Dead-Letter Queue Poison Pill Quarantine Protocol

#### Context & Problem Statement
The dead-letter queue (DLQ) replay endpoint (`POST /api/v1/telemetry/dlq/replay`) clears the DLQ and re-submits events to `EventNormalizationService.normalize()`. If an event has a fatal structural error (such as a corrupt field or type-casting violation), it re-triggers the exception and immediately re-enters the DLQ. Unchecked replay invocations result in infinite replay loops and CPU/log thrashing.

#### Decision
1. Maintain an integer counter `dlq_replay_count` in each dead-letter queue payload.
2. Increment `dlq_replay_count` each time an event is submitted for replay.
3. If an event exceeds the maximum retry threshold (`dlq_replay_count >= 3`), classify the event as a permanent poison pill and transfer it to an isolated in-memory quarantine queue (`poisonPillQueue`).
4. Prevent quarantined poison pills from being re-ingested into active evaluation pipelines.

---

### ADR-010: Incident Investigation, Evidence Provenance, and Lifecycle State Enforcement (Milestone M4)

#### Context & Problem Statement
Security operations workflows require analysts to triage detection findings, aggregate forensic evidence, correlate related detections, assign responsibilities, track notes, and enforce auditable incident state transitions. Introducing a redundant "Investigation" root entity alongside "Incident" creates synchronization bugs and fragmented state. Additionally, premature incident closure without rationale or closure review compromises compliance auditability.

#### Decision
1. **Unified Incident Entity Model**: An investigation is modeled directly as an analyst workflow operating on the `Incident` entity, linked `IncidentFinding` records, and dynamic `IncidentEvidenceDto` objects.
2. **Finding Status Synchronization**: Associating a detection finding to an incident transitions its status from `OPEN` to `LINKED_TO_INCIDENT`. Detaching a finding from an incident cleanly restores its status to `OPEN` and updates the timeline.
3. **Forensic Evidence Provenance**: Evidence is not duplicated into separate tables. Instead, `GET /api/v1/incidents/{id}/evidence` resolves the finding's `relatedDocId` directly against the stored normalized event buffer, surfacing raw immutable telemetry (`event.getOriginal()`), normalized ECS fields, provider source, and asset metadata.
4. **Multi-Factor Related Finding Correlation**: `GET /api/v1/detections/findings/{id}/related` surfaces candidate findings correlated across shared asset hostnames (confidence 0.90), shared source IPs (confidence 0.85), identical detection rules (confidence 0.75), and shared MITRE ATT&CK tactics (confidence 0.70).
5. **Strict Lifecycle Gatekeeping**: State transitions are enforced by `IncidentStateMachine`:
   - Direct transitions from `NEW` to `RESOLVED` or `CLOSED` are rejected.
   - Transition to `RESOLVED` strictly requires a non-blank `resolutionRationale`.
   - Transition to `CLOSED` strictly requires prior `RESOLVED` or `FALSE_POSITIVE` state and records `closedAt`, `closedBy`, and mandatory `closureNotes`.
   - Reopening transitions `RESOLVED` or `CLOSED` to `REOPENED` with mandatory justification.
