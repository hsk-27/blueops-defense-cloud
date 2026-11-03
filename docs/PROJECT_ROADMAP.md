# BlueOps — Project Engineering Roadmap & Execution Plan

## 1. Project Overview
**Platform Name:** BlueOps — Enterprise Threat Detection & Automated Incident Response Platform  
**Architecture:** Modular Monolith (Spring Boot 3.3+ / Java 23 / PostgreSQL / OpenSearch / React 18+ Vite TypeScript / Fluent Bit / Atomic Red Team)  
**Target Resource Profile:** 16 GB RAM Host, single-node OpenSearch, constrained JVM heaps, modular deployment.

---

## 2. Phase Breakdown & Execution Status

| Phase | Description | Status | Exit Criteria |
|---|---|---|---|
| **Phase 0** | Workspace Audit & Planning | **COMPLETED** | Environment audited, directory skeleton initialized, memory files established |
| **Phase 1** | Infrastructure Foundation | **COMPLETED** | Docker Compose, PostgreSQL, OpenSearch cluster, Dashboards, volume persistence |
| **Phase 2** | Backend Foundation | **COMPLETED** | Spring Boot 3 modular monolith, JPA, Flyway, Spring Security, JWT RBAC, Actuator |
| **Phase 3** | Telemetry & Normalization | **COMPLETED** | Fluent Bit pipelines, BlueOps Common Event Schema, Sysmon/Auditd/Suricata mappings |
| **Phase 4** | Detection Engineering | **COMPLETED** | 18 Sigma-compatible rules (Windows/Linux/Network), 4 correlation scenarios |
| **Phase 5** | Operational Backend | **COMPLETED** | Asset, Detection, Incident lifecycle, IOC threat intel, Findings sync, Audit log |
| **Phase 6** | Frontend SOC Dashboard | **COMPLETED** | React 18 + TS + Tailwind SOC dashboard, Incident Center, Investigation workspace |
| **Phase 7** | Response Orchestration | **COMPLETED** | Signed HMAC simulation & restricted lab agent, P001-P007 playbooks, rollback |
| **Phase 8** | Validation & Testing | **COMPLETED** | Atomic Red Team T001-T010 scenarios, benign baseline, precision/recall/MTTD metrics |
| **Phase 9** | Documentation & Release | **COMPLETED** | Comprehensive documentation, architecture diagrams, runbooks, portfolio delivery |
| **Phase 10** | Master Audit & Remediation | **COMPLETED** | 24-Dimension accreditation, AppSec hardening, dynamic benchmarks (95.0 / 100) |
| **Phase 11** | IEEE Research Submission | Horizon | Camera-ready manuscript based on empirical benchmark datasets in `test-lab/results/` |

---

## 3. Engineering Decisions & Conventions
1. **Separation of Concerns:** Raw and normalized telemetry stays in OpenSearch. High-level findings and operational incident records reside in PostgreSQL.
2. **Deterministic Detection:** No black-box autonomous AI detection in core loop. All rules follow Sigma syntax and MITRE ATT&CK technique mapping.
3. **Defense-in-Depth Response:** Remote response execution prohibits arbitrary shell commands. Only allowlisted, HMAC-signed, expiring, verified, and reversible actions execute against designated lab assets.
4. **Memory Constraint:** OpenSearch heap bounded at `-Xms1g -Xmx1g`, Spring Boot bounded at `-Xms256m -Xmx512m`.
