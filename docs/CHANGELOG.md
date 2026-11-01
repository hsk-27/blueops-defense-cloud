# BlueOps — Project Changelog

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
