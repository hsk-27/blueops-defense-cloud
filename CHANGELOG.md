# Changelog

All notable changes to the BlueOps platform will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [1.2.1] - 2026-11-20

### Added
- **Core Governance Architecture Documentation:** Created authoritative system documentation mandated by Master Project Development Directive:
  - `ARCHITECTURE.md`: Complete system architecture, component breakdown, CES v1.0.0 specification, data flow, and boundaries.
  - `DEVELOPMENT_ROADMAP.md`: Prioritized engineering backlog categorized by P0, P1, P2, P3, and P4 tasks.
  - `TESTING.md`: Complete testing matrix, empirical verification baseline (46 JUnit tests, 6 Vitest tests, 10 Atomic Red Team, 50 Benign Baselines, 8 Deceptive Attacks, 5 Boundary Tests).
  - `RESEARCH_NOTES.md`: Literature mapping, comparative system analysis (Wazuh, Elastic Security, Security Onion), and candidate applied research proposals.
  - `CHANGELOG.md`: Version tracking and changelog history.
- **Enhanced Test Suites:**
  - Added parameterized production alias tests and Shannon entropy boundary tests in `SecurityStartupValidatorTest.java` (9/9 passed).
  - Added multi-threaded concurrent query test in `SigmaRuleParserAndRegistryTest.java` (4,000 queries across 8 reader threads during disk reload with 0 errors/empty reads).
  - Added CLI argument injection, whitespace injection, and sliding-window replay tests in `response-agent/tests/test_agent.py`.

### Security & Correctness Remediations (Phase II - P0)
- **SEC-001 (Cryptographic Startup Validation):**
  - Implemented true Shannon Information Entropy calculation ($H(X) = -\sum P(x) \log_2 P(x)$) requiring $H \ge 3.0$ bits/character and minimum 8 unique characters.
  - Added detection and rejection of predictable keys (e.g., identical repeated characters, repeated 4-character chunks, or repeated halves).
  - Expanded production profile detection to all enterprise aliases (`prod`, `production`, `prd`, `live`).
- **SEC-002 (Response Agent Security Boundary):**
  - Replaced bulk nonce clearing (`.clear()` at 10,000 items) with a sliding time-window TTL cache (`time.time() - 65s`), providing 100% replay immunity across cache operations.
  - Added strict defense against CLI option injection (rejecting targets starting with `-`) and argument injection (rejecting whitespace).
  - Added action-specific semantic target validation (IPv4/IPv6 CIDR for IP actions, POSIX usernames for account actions, hostnames for isolation).
- **SEC-003 (Sigma Rule Registry Concurrency):**
  - Replaced mutable HashMap cleared during disk traversal with an atomic reference swap (`AtomicReference<Map<String, SigmaRuleDefinition>>`).
  - Staged rules into temporary collections and atomically committed them, ensuring continuous zero-downtime query availability.
  - Added collision detection and warning logs when duplicate rule codes or IDs are encountered.

### Fixed
- **CI & Build Integrity:**
  - Resolved 5 TypeScript compilation errors in `frontend/src/pages/IncidentCenterPage.tsx`, `LiveTelemetryPage.tsx`, `InvestigationWorkspacePage.tsx`, and `services/api.ts`, enabling clean production builds (`npm run build`).
  - Updated `backend/Dockerfile` to use `maven:3.9.6-eclipse-temurin-21-alpine` with pre-bundled Maven, avoiding network wrapper download failures in container builds.
  - Configured `PYTHONPATH: .` and `python -m pytest` in GitHub Actions CI workflow for the response agent test runner.
- **Security Policy:** Updated `SECURITY.md` with explicit mathematical Shannon entropy standards ($H \ge 3.8$ bits/byte), sliding-window anti-replay guarantees, CLI argument-injection defenses, and simulation-only defaults.

---

## [1.2.0] - 2026-11-17

### Added
- Dynamic Sigma YAML rule parser and registry (`SigmaRuleParser`, `SigmaRuleRegistry`).
- Runtime rule reload REST endpoint (`POST /api/v1/detections/reload`).
- Security startup validation bean (`SecurityStartupValidator`) verifying secret length and checking hardcoded keys in `prod`.
- Frontend Sigma rule management interface (`DetectionManagementPage.tsx`) with catalog viewing and dynamic reload button.
- Modular host response drivers (`SimulationDriver`, `LinuxDriver`, `WindowsDriver`).

---

## [1.1.0] - 2026-11-14

### Added
- Common Event Schema (CES v1.0.0) with in-memory ring buffer and dead-letter queue.
- 18 single-event detection rules (D001–D018) mapping to MITRE ATT&CK techniques.
- 4 multi-stage scenario correlation engines (C001–C004).
- Threat intelligence indicator ingestion and matching service.
- Python-based response agent with HMAC-SHA256 signature verification and 60s anti-replay window.
- Adversary simulation suite and empirical benchmark testing framework.
