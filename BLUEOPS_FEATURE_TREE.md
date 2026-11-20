# BLUEOPS FEATURE TREE & SUBSYSTEM TAXONOMY

**Document Version:** 2.0.0  
**Classification:** Functional Feature Hierarchy & Branch Mapping  
**System Document ID:** BLUEOPS-TREE-2026-001  

---

## 1. THE HIERARCHICAL STRUCTURE

In accordance with **Architectural Invariant 1**, all features in BlueOps branch strictly from the central operational spine:

```
                          [THE OPERATIONAL SPINE]
                                     │
     ┌───────────┬───────────┬───────┴───┬───────────┬───────────┐
     │           │           │           │           │           │
 [Branch A]  [Branch B]  [Branch C]  [Branch D]  [Branch E]  [Branch F]
  Detection   Context &   Investi-    Correla-    Response    Reliability
  Expansion  Enrichment   gation       tion       Orchestr.
     │                                                           │
     └───────────────────────┬───────────────────────────────────┘
                             │
                     ┌───────┴───────┐
                     │               │
                 [Branch G]      [Branch H]
                  Platform        Research &
                 Operations       Experiment
```

Every capability must have an unambiguous parent branch and priority tier.

---

## 2. PRIORITY DEFINITIONS

- **P0 — Core Integrity:** Security vulnerabilities, data corruption bugs, authentication bypasses, broken critical error paths, and mathematical/logical errors in core evaluators.
- **P1 — Spine Completion:** Capabilities required to execute the complete end-to-end event-to-simulated-response lifecycle.
- **P2 — Spine Strengthening:** Reliability improvements, correlation accuracy, query performance, and operational UX enhancements.
- **P3 — Branch Expansion:** Additional detection rules, threat intelligence feed sync, advanced investigation graph views, and live response drivers.
- **P4 — Research & Experimental Extensions:** Novel heuristic scoring, automated adversary emulation benchmarks, and machine learning anomaly experiments.
- **P5 — Nonessential / Convenience:** Cosmetic styling improvements, optional third-party integrations, and developer convenience shortcuts.

---

## 3. BRANCH-BY-BRANCH TAXONOMY

### Branch A: Detection Expansion (Serves Stage 3: Detection)
*Focus: Strengthening the accuracy, breadth, and maintainability of detection logic.*

| Feature ID | Feature Name | Priority | Dependencies | Status | Description |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **FEAT-A01** | Dynamic Sigma AST Evaluator | P0 | Core B (CES) | Implemented | Evaluates boolean ASTs (`and`, `or`, `not`) against normalized events in-memory. |
| **FEAT-A02** | Sliding-Window Aggregation Engine | P0 | FEAT-A01 | Implemented | Stateful sliding-window event counting (`\| count() > N by entity`) and sequence correlation in `SigmaAggregationEngine`. |
| **FEAT-A03** | Thread-Safe Rule Registry Reload | P1 | FEAT-A01 | Implemented | Swaps active rule map atomically via `AtomicReference` with rollbacks on parse failure. |
| **FEAT-A04** | Rule Syntax & Schema Validator | P1 | FEAT-A01 | Implemented | Validates mandatory Sigma YAML keys, modifiers, and MITRE tags before registry indexing. |
| **FEAT-A05** | Extended Rule Catalog (Rules 19–50) | P3 | FEAT-A02 | Backlog | Expands coverage across cloud (AWS CloudTrail), container (Docker/K8s), and identity telemetry. |
| **FEAT-A06** | OpenSearch Query Translator | P3 | Core E (OpenSearch)| Backlog | Translates Sigma rules into OpenSearch Query DSL for retrospective threat hunting. |

### Branch B: Context & Enrichment (Serves Stage 4: Contextualization)
*Focus: Connecting isolated telemetry events to enterprise assets and global threat intelligence.*

| Feature ID | Feature Name | Priority | Dependencies | Status | Description |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **FEAT-B01** | Asset Criticality & Inventory Registry | P1 | PostgreSQL | Implemented | Tracks hostnames, IP addresses, OS types, and criticality levels (`CRITICAL`, `HIGH`, `LOW`). |
| **FEAT-B02** | Threat Intelligence IOC Matching | P1 | Core B (CES) | Implemented | Matches IP addresses, domains, and SHA256 hashes against relational IOC indicator tables. |
| **FEAT-B03** | Authoritative Advisory Guidance System | P2 | Core F (Incident)| Implemented | Maps triggered findings to NIST SP 800-61, CISA, and MITRE remediation recommendations. |
| **FEAT-B04** | Automated STIX/TAXII Feed Ingestion | P3 | FEAT-B02 | Backlog | Periodically polls public threat feeds (e.g. AlienVault OTX, AbuseIPDB) to update IOC tables. |

### Branch C: Investigation (Serves Stage 5: Investigation)
*Focus: Enabling rapid, evidence-grounded human triage and forensic discovery.*

| Feature ID | Feature Name | Priority | Dependencies | Status | Description |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **FEAT-C01** | Finding Detail & Raw Evidence Provenance | P1 | Core E (Findings)| Implemented | Resolves `relatedDocId` to raw stored telemetry and ECS fields via `IncidentEvidenceDto` (`/api/v1/incidents/{id}/evidence`). |
| **FEAT-C02** | Temporal Process Execution Hierarchy | P2 | Core B (CES) | Implemented | Renders parent-child process execution trees (`ParentImage` $\rightarrow$ `Image` $\rightarrow$ `CommandLine`). |
| **FEAT-C03** | Multi-Entity Timeline & Audit View | P2 | Core E (Findings)| Implemented | Interleaved chronological lifecycle milestones (`INCIDENT_CREATED`, `STATUS_CHANGE`, `FINDING`, `NOTE`, `CLOSURE`). |
| **FEAT-C04** | Related Finding Correlation Engine | P1 | FEAT-C01 | Implemented | Discovers candidate findings correlated across shared asset, source IP, rule, or tactic with confidence scoring. |
| **FEAT-C05** | Interactive Attack Graph Explorer | P3 | FEAT-C03 | Backlog | Node-link visualization of adversary lateral movement across connected network entities. |

### Branch D: Correlation & Incident Management (Serves Stage 6: Decision & Incident Management)
*Focus: Synthesizing low-level findings into high-confidence attack chains and enforcing auditable workflows.*

| Feature ID | Feature Name | Priority | Dependencies | Status | Description |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **FEAT-D01** | Multi-Stage Kill-Chain Scenarios (C001, C002)| P1 | Core C (Findings)| Implemented | Correlates sequences of findings on the same asset within a 15-minute sliding window. |
| **FEAT-D02** | Automated Incident Synthesis & Manual Promotion | P1 | FEAT-D01 | Implemented | Auto-creates or promotes findings to `Incident` with finding status synchronization (`LINKED_TO_INCIDENT` / `OPEN`). |
| **FEAT-D03** | Strict Lifecycle State Machine & Gatekeeping | P1 | Core F (Incident)| Implemented | Enforces valid transitions; mandates rationale for `RESOLVED` and formal review notes for `CLOSED`. |
| **FEAT-D04** | Operational Incident Priority & SLA Layer | P1 | Core F (Incident)| Implemented | Distinct operational priorities (`P1_CRITICAL` through `P4_LOW`) mapped from technical severity. |
| **FEAT-D05** | Cross-Asset Lateral Movement Correlation | P2 | FEAT-D01 | Backlog | Correlates suspicious authentication or network hops between distinct enterprise assets. |
| **FEAT-D06** | Anomaly & Heuristic Score Aggregation | P3 | FEAT-D01 | Backlog | Computes composite entity risk scores based on finding volume, severity, and temporal proximity. |

### Branch E: Response (Serves Stage 7: Controlled Response)
*Focus: Enforcing safe, policy-governed containment actions across endpoints.*

| Feature ID | Feature Name | Priority | Dependencies | Status | Description |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **FEAT-E01** | Pre-Execution Policy Boundary Validator | P0 | FEAT-B01 (Asset) | Implemented | Blocks containment actions against loopback, gateway, or unauthorized critical infrastructure. |
| **FEAT-E02** | Cryptographic HMAC-SHA256 & Nonce Agent Auth | P0 | Response Agent | Implemented | Signs all agent requests and caches nonces in sliding TTL window to defeat replay attacks. |
| **FEAT-E03** | Safe Simulation Execution Mode | P1 | Response Agent | Implemented | Verifies playbook syntax, host connectivity, and driver logic without modifying OS state. |
| **FEAT-E04** | Reversible Playbook Execution & Rollback | P1 | Response Agent | Implemented | Enforces matching undo actions (`block_ip` $\leftrightarrow$ `restore_ip`) for every containment step. |
| **FEAT-E05** | Production OS Driver Implementations | P3 | Response Agent | Partial | Replaces stubbed `isolate_host` / `collect_evidence` methods with native Windows/Linux scripts. |

### Branch F: Reliability (Cross-Cutting Platform Resilience)
*Focus: Preventing event loss, managing memory limits, and guaranteeing recovery.*

| Feature ID | Feature Name | Priority | Dependencies | Status | Description |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **FEAT-F01** | Dead-Letter Queue (DLQ) & Cyclic Loop Guard | P0 | Core B (Normaliz)| Partial | Traps corrupted events; requires poison-pill classification to prevent infinite replay loops. |
| **FEAT-F02** | OpenSearch Downstream Fallback Buffer | P1 | Core E (OpenSearch)| Implemented | In-memory concurrent store preserves findings and incidents if OpenSearch is unreachable. |
| **FEAT-F03** | Multi-Worker Nonce Cache Synchronization | P0 | Response Agent | **Backlog** | Replaces in-process Python dict with Redis or file-locked SQLite to prevent multi-worker replays. |
| **FEAT-F04** | High-Throughput Ring Buffer Management | P2 | Core B (Normaliz)| Implemented | Bounded concurrent deque (1,000 events) guarantees zero memory exhaustion under traffic spikes. |

### Branch G: Platform Operations (Cross-Cutting Governance)
*Focus: Authentication, role separation, configuration integrity, and auditing.*

| Feature ID | Feature Name | Priority | Dependencies | Status | Description |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **FEAT-G01** | Cryptographic Startup Entropy Verification | P0 | Spring Boot | Partial | Validates JWT/HMAC secrets on startup; requires mathematical keyspace check over Shannon length. |
| **FEAT-G02** | Role-Based Access Control (RBAC) | P1 | Spring Security | Implemented | Enforces strict route permissions: `ROLE_ADMIN`, `ROLE_ANALYST`, and `ROLE_VIEWER`. |
| **FEAT-G03** | Immutable Security Audit Trail | P1 | PostgreSQL | Implemented | Logs all login attempts, incident status modifications, and response executions. |
| **FEAT-G04** | Container Health Probes & Actuator Metrics | P2 | Spring Actuator | Implemented | Exposes `/actuator/health` and `/actuator/metrics` for orchestrator liveness and readiness checks. |

### Branch H: Research & Experimental Extensions (Isolated Sandbox)
*Focus: Academic investigation and empirical defensibility without contaminating core stability.*

| Feature ID | Feature Name | Priority | Dependencies | Status | Description |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **FEAT-H01** | Automated Adversary Emulation Testbed | P2 | Core Platform | Implemented | Replays multi-stage Atomic Red Team attack scenarios (`test-lab/run_simulations.js`). |
| **FEAT-H02** | Deceptive Attack Evasion Evaluation Suite | P2 | Response Agent | Implemented | Measures detection resiliency against obfuscated, encoded, and path-traversal evasion attempts. |
| **FEAT-H03** | Detection Latency & Memory Profiling Lab | P3 | Core Platform | Backlog | Empirically profiles processing latency (p50, p95, p99) under simulated 10k EPS load. |
