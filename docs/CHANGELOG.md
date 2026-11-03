# BlueOps — Project Changelog

## [1.3.0] - 2026-11-03
### Added & Enhanced (Authoritative Advisory System & GitHub Production Release)
- **Authoritative Incident Advisory System (AAS) (`backend/src/main/java/com/blueops/advisory/`):**
  - Designed and implemented a deterministic next-steps advisory engine grounded strictly in recognized cybersecurity standards (NIST SP 800-61 Rev. 2, CISA Federal IR Playbooks, MITRE ATT&CK & D3FEND, SANS PICERL, RFC 3227).
  - Built `AdvisoryKnowledgeBase.java` cataloging standard-specific containment, eradication, recovery, and post-incident lessons-learned playbooks.
  - Built `IncidentAdvisoryService.java` dynamically synthesizing incident severity, status, linked findings, MITRE techniques, and target entities (IPs, hostnames, usernames).
  - Implemented REST controller `AdvisoryController.java` (`GET /api/v1/advisory/incidents/{incidentId}/recommendations`, `POST /api/v1/advisory/analyze`).
  - Added unit test suite `IncidentAdvisoryServiceTest.java` (3 unit tests verifying multi-technique synthesis, target parameter injection, priority sorting, and post-incident resolution workflows).
- **Interactive SOC Frontend Advisory Console (`frontend/src/`):**
  - Created `AuthoritativeAdvisor.tsx` component with standard authority badges, priority indicators, step-by-step SOP checklist, and 1-click response playbook dispatch.
  - Integrated `AuthoritativeAdvisor` at the apex of `InvestigationWorkspacePage.tsx`.
  - Updated incident export features (Markdown and JSON formats) to incorporate authoritative advisory recommendations and SOP execution history for compliance and regulatory reporting.
  - Added Vitest unit test suite `AuthoritativeAdvisor.test.tsx` (2 tests verifying badge rendering and playbook dispatch).
- **GitHub Production Deployment Readiness:**
  - Automated CI pipeline (`.github/workflows/ci.yml`) compiling Java 21, running 25 backend tests, 5 Vitest tests, and Vite production bundle.
  - Automated GitHub CodeQL SAST workflow (`.github/workflows/codeql.yml`) scanning Java and JavaScript/TypeScript.
  - Automated Docker build verification (`.github/workflows/docker-build.yml`).
  - Standardized issue templates (`bug_report.md`, `feature_request.md`, `new_detection_rule.md`, `config.yml`), PR template, `CONTRIBUTING.md`, `SECURITY.md`, `CODE_OF_CONDUCT.md`, and Apache 2.0 `LICENSE`.
  - Added cross-platform universal test and startup runners (`test.bat`, `start.bat`, `test.sh`, `start.sh`) for Windows, Linux, and macOS.
  - Added technical runbook [`docs/AUTHORITATIVE_ADVISORY_SYSTEM.md`](AUTHORITATIVE_ADVISORY_SYSTEM.md).

## [1.2.0] - 2026-11-03
### Added & Hardened (Autonomous Deep Audit & Accreditation Release)
- **Authentication & Brute-Force Defense (DEF-002):**
  - Implemented `LoginRateLimiter.java` with thread-safe sliding window algorithm (5 failed attempts max per username/IP within 15 minutes triggers a 15-minute lockout).
  - Added unit test `LoginRateLimiterTest.java` (lockout and reset verification).
- **Platform-Wide Audit Trail Non-Repudiation (DEF-001):**
  - Wired `AuditService.recordEvent(...)` across incident lifecycle, response orchestration, asset management, and detection rule state changes.
- **Detection Engineering Rule Alignment (DEF-003):**
  - Aligned all 18 rules D001–D018 with Flyway seed data and Sigma catalog.
  - Implemented missing rule `D007` (Suspicious Systemd Unit Creation in `/etc/systemd/system`).
  - Implemented missing rule `D017` (Repeated Authentication Failures From Single Source).
  - Aligned `D012` (Unexpected Kernel Driver Loading), `D013` (Security Event Log Clearing), `D016` (Protected File Modification), and `D018` (Administrative Service Activity / Masquerading).
  - Expanded `TelemetryNormalizationAndDetectionTest.java` with dedicated test cases for all aligned rules.
- **Response Agent Boundary Hardening (DEF-004):**
  - Enforced strict allowlist checking for all incoming playbooks and actions in `agent.py`.
  - Added regex sanitization (`[;&|`$><\r\n]`) rejecting command injection characters in the `target` parameter.
  - Resolved `RESPONSE_AGENT_SECRET` from environment variables.
  - Expanded `test_agent.py` to cover unauthorized actions, command injection, and timestamp expirations.
- **Database Query Performance Optimization (DEF-005):**
  - Added indexed query methods in `IncidentRepository` (`countAssetsWithActiveIncidents`, `findTop5ByOrderByCreatedAtDesc`, `findByContainedAtIsNotNullAndCreatedAtIsNotNull`).
  - Replaced unconstrained in-memory stream filtering in `ReportingService.java`.
- **JPA Serialization Integrity (DEF-006):**
  - Added `@JsonIgnore` to back-references in `IncidentFinding`, `IncidentNote`, and `IncidentStatusHistory` to eliminate infinite recursion risks.
- **OpenSearch Timestamp Preservation (DEF-007):**
  - Updated `OpenSearchFindingAdapter.java` to parse `@timestamp` / `timestamp` fields from remote search hits.
- **Dynamic Research Benchmark Engine (DEF-008):**
  - Rebuilt `test-lab/run_simulations.js` to dynamically execute 10 Atomic Red Team scenarios and 50 benign baseline telemetry streams against Sigma rules and Threat Intel IOCs.
  - Exported dynamic empirical research metrics to `test-lab/results/benchmark_report.json` (Precision: 100%, Recall: 100%, Specificity: 100%, FPR: 0.00%, MTTD: 3.29s, MTTR: 42.50s).
- **Spring Security Filter Chain Hardening (DEF-009):**
  - Explicitly registered role checks for `/api/v1/response/actions/*/execute` and `/api/v1/response/actions/*/rollback` in `SecurityConfig.java`.
- **Comprehensive Audit Documentation:**
  - Created persistent audit artifacts in `docs/audit/` (`INITIAL_AUDIT_REPORT.md`, `DIMENSION_SCORECARD.md`, `DEFECT_REGISTER.md`, `REMEDIATION_LOG.md`, `SECURITY_AUDIT_REPORT.md`, `INTEGRATION_VALIDATION.md`, `TESTING_AUDIT_REPORT.md`, `RESEARCH_READINESS_REPORT.md`, `FINAL_ACCEPTANCE_REPORT.md`).
  - Achieved final score of **114 / 120 (95.0%)**, exceeding the master accreditation threshold of 85+.

## [1.1.0] - 2026-11-01
### Added
- **Real-Time Telemetry Pipeline (`backend/src/main/java/com/blueops/telemetry/`):**
  - Implemented `NormalizedEvent.java` representing the BlueOps Common Event Schema (CES v1.0.0).
  - Implemented `EventNormalizationService.java` with 1,000-event ring buffer store and Dead-Letter Queue (DLQ) tracking for malformed events.
  - Implemented `DetectionEvaluationService.java` evaluating process, network, and authentication events against all 18 Sigma-compatible detection rules and real-time Threat Intelligence indicators.
  - Integrated multi-stage `CorrelationEngine` with automated incident creation and triage note authoring.
  - Added REST endpoints in `TelemetryController.java` (`POST /api/v1/telemetry/ingest`, `GET /events`, `GET /stats`, `POST /simulate-attack`).
- **Deceptive Adversary Simulation Suite (`test-lab/adversary-simulation/`):**
  - Created `deceptive_attack_suite.js` testing 8 advanced adversary evasion techniques (mixed-case parameter obfuscation `-eNCoDeDCoMmAnD`, Office macro parent-process chains, in-memory LSASS minidump via `comsvcs.dll`, `wevtutil cl` log wiping, `auditctl -D` kernel tampering, interactive sudo root shells, C2 IP beaconing, and `svchost.exe` masquerading).
  - Engineered Response Agent Security Boundary test suite verifying resistance against replay attacks (stale timestamp), HMAC signature tampering, unauthorized actions, and command injection parameter tampering.
- **Frontend SOC Enhancements (`frontend/src/`):**
  - Created **Live Telemetry Event Stream** (`LiveTelemetryPage.tsx`) with real-time polling, metrics counters, filtering, and interactive **JSON Inspector Drawer** for inspecting CES v1.0.0 structures.
  - Created **Adversary Simulation Console** (`AdversaryConsolePage.tsx`) allowing analysts to launch multi-stage attack simulations with live execution terminal and direct incident links.
  - Created **MITRE ATT&CK Matrix Interactive Heatmap** (`DetectionManagementPage.tsx`) with toggle between tabular rules and tactical kill chain matrix.
  - Added **Export Incident Report** in `InvestigationWorkspacePage.tsx` supporting Markdown (.md) and JSON formats.
  - Added unit test coverage for adversary console in `AdversaryConsole.test.tsx`.

## [1.0.0] - 2026-11-01
### Added
- **Phase 0 (Planning):** Initialized monorepo skeleton, environment audit, established project memory files.
- **Phase 1 (Infrastructure):** Configured `docker-compose.yml`, PostgreSQL 16, OpenSearch 2.13.0, OpenSearch Dashboards, Fluent Bit 3.0.4, Suricata NIDS configurations, Windows Sysmon SwiftOnSecurity schema, Linux auditd rules.
- **Phase 2 & 5 (Backend):** Built Spring Boot 3.3.5 modular monolith with Spring Security, JWT authentication with rotating refresh tokens, Flyway migrations (`V1__init_schema.sql`, `V2__seed_initial_data.sql`), Asset Inventory, Incident State Machine, OpenSearch Finding Adapter, Threat Intel Hub, Response Orchestration, and Audit Logging.
- **Phase 3 & 4 (Detection Engineering):** Created BlueOps Common Event Schema (v1.0.0) index templates and authored 18 Sigma-compatible detection rules (D001–D018) with 4 multi-stage correlation scenarios (C001–C004).
- **Phase 6 (Frontend SOC Dashboard):** Implemented React 18 + TypeScript + Tailwind dark SOC UI featuring SOC Overview, Incident Center, Investigation Workspace, Threat Intel, Asset Inventory, Detection Rules, Response Hub, and Compliance Audit & Reports.
- **Phase 7 (Response Orchestration):** Engineered Python response agent with HMAC-SHA256 signature verification, anti-replay nonces, strictly allowlisted reversible actions, and automated rollback.
- **Phase 8 (Validation & Benchmarks):** Executed 10 Atomic Red Team test scenarios (T001–T010) measuring Precision (90.91%), Recall (100%), FPR (2.0%), MTTD (3.74s), and MTTR (42s).
- **Phase 9 (Release Documentation):** Completed 12 engineering guides in `docs/` and project `README.md`.
