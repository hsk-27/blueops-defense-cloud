# BLUEOPS TECHNICAL AUDIT: COMPLETE FILE INVENTORY
**Document ID:** BLUEOPS-AUDIT-INV-001  
**Scope:** Categorized First-Party File Inventory across all 244 Git-Tracked Repository Files  
**Target Codebase:** `blueops-defense-cloud`  
**Classification:** Technical Due Diligence & Codebase Demographics  

---

## 1. Inventory Summary by Functional Tier

```
Tiers & Categories                                Files      Approx. LOC
────────────────────────────────────────────────────────────────────────
1. Repository Root & CI/CD Workflows                 18          1,150
2. Backend Core (Java 21 / Spring Boot 3.3.5)       102          6,909
   ├─ Domain Packages (Controllers/Services/DTOs)    86          5,520
   ├─ Automated Test Classes                          8            780
   └─ Build & Database Migration Resources            8            609
3. Frontend Presentation (React 18 / TypeScript)     36          4,471
   ├─ Application Core & View Pages                  12          2,940
   ├─ Reusable UI Components                          6            720
   ├─ Context, Services & Types                       4            410
   ├─ UI Component Tests                              4            190
   └─ Build Tooling & Configuration                   10           211
4. Detection Rules (Sigma YAML Specifications)       19            720
5. Infrastructure & Ingestion Configuration          11            580
6. SOAR Restricted Response Agent (Python)            5            320
7. Test Lab & BAS Adversary Simulation Engine         7          1,180
8. Master Architecture & Operational Documentation   46          4,320
────────────────────────────────────────────────────────────────────────
TOTAL TRACKED REPOSITORY FILES                      244        ~17,650
```

---

## 2. Categorized File-by-File Breakdown

### 2.1. Repository Root & CI/CD Workflows (18 Files)
* `.dockerignore` (Config, 15 LOC) — Excludes build artifacts from top-level Docker context.
* `.env.example` (Config, 35 LOC) — Template environment variables for ports, credentials, and secrets.
* `.gitattributes` (Config, 10 LOC) — Enforces LF line endings across multi-platform developer machines.
* `.gitignore` (Config, 45 LOC) — Excludes compiled jars, node_modules, logs, and zip archives.
* `.github/workflows/ci.yml` (YAML, 78 LOC) — GitHub Actions CI pipeline running Maven compile, JUnit tests, and Vitest.
* `.github/workflows/codeql.yml` (YAML, 42 LOC) — Static analysis security scanning for Java and JavaScript/TypeScript.
* `.github/workflows/docker-build.yml` (YAML, 55 LOC) — Automated container image build and smoke tests.
* `.github/ISSUE_TEMPLATE/bug_report.md` (Markdown, 32 LOC) — Bug report template.
* `.github/ISSUE_TEMPLATE/feature_request.md` (Markdown, 28 LOC) — Feature request template.
* `.github/ISSUE_TEMPLATE/new_detection_rule.md` (Markdown, 45 LOC) — Sigma detection rule proposal template.
* `.github/ISSUE_TEMPLATE/config.yml` (YAML, 12 LOC) — GitHub Issue configuration.
* `.github/PULL_REQUEST_TEMPLATE.md` (Markdown, 30 LOC) — Standard PR checklist and verification template.
* `CODE_OF_CONDUCT.md` (Markdown, 85 LOC) — Contributor Covenant Code of Conduct.
* `CONTRIBUTING.md` (Markdown, 110 LOC) — Developer workflow, branch strategies, and PR guidelines.
* `GITHUB_DEPLOYMENT_GUIDE.md` (Markdown, 95 LOC) — Step-by-step GitHub Desktop and CLI publishing runbook.
* `LICENSE` (Text, 21 LOC) — Apache 2.0 open-source software license.
* `README.md` (Markdown, 280 LOC) — Master project overview, quick-start guide, and architecture summary.
* `SECURITY.md` (Markdown, 55 LOC) — Vulnerability disclosure policy and reporting contacts.

---

### 2.2. Backend Core (Java 21 / Spring Boot 3.3.5) (102 Files)

#### Application Root & Infrastructure (3 Files)
* `backend/pom.xml` (Maven XML, 181 LOC) — Dependencies for Spring Boot 3.3.5, Security, JPA, JJWT, OpenAPI, Postgres, H2.
* `backend/Dockerfile` (Dockerfile, 35 LOC) — Multi-stage distroless Eclipse Temurin Java 21 container definition.
* `backend/src/main/java/com/blueops/BlueOpsApplication.java` (Java, 28 LOC) — Spring Boot application entry point.

#### Advisory Subsystem (`com.blueops.advisory`) (8 Files)
* `AdvisoryController.java` (Java, 48 LOC) — REST endpoints for incident recommendations and ad-hoc analysis.
* `AdvisoryKnowledgeBase.java` (Java, 175 LOC) — Authoritative catalog citing NIST SP 800-61r2, CISA, MITRE D3FEND, and SANS.
* `AdvisoryPhase.java` (Java, 18 LOC) — Incident lifecycle phases (Containment, Eradication, etc.).
* `AdvisoryPriority.java` (Java, 14 LOC) — Priority enumeration (Immediate Action, High Priority, etc.).
* `AuthoritativeSource.java` (Java, 16 LOC) — Regulatory citation source enum (NIST, CISA, MITRE, SANS).
* `IncidentAdvisoryService.java` (Java, 155 LOC) — Synthesis engine matching findings to regulatory playbooks.
* `IncidentRecommendationDto.java` (Java, 52 LOC) — Structured recommendation data transfer object.
* `AdvisoryAnalysisRequest.java` (Java, 24 LOC) — Request DTO for ad-hoc advisory queries.

#### Asset Management (`com.blueops.assets`) (6 Files)
* `Asset.java` (Java, 65 LOC) — JPA entity representing monitored hosts and endpoints.
* `AssetController.java` (Java, 72 LOC) — Endpoints for querying, registering, and updating assets.
* `AssetDto.java` (Java, 42 LOC) — Asset data transfer object.
* `AssetRepository.java` (Java, 20 LOC) — Spring Data JPA repository for asset records.
* `AssetService.java` (Java, 85 LOC) — Asset lifecycle and telemetry status management.
* `AssetStatus.java` (Java, 15 LOC) — Asset status enum (ONLINE, OFFLINE, ISOLATED, COMPROMISED).

#### Audit Trail (`com.blueops.audit`) (4 Files)
* `AuditController.java` (Java, 42 LOC) — Query endpoints for compliance audit trail.
* `AuditLog.java` (Java, 58 LOC) — Immutable JPA entity recording administrative and security actions.
* `AuditLogRepository.java` (Java, 18 LOC) — Spring Data JPA repository for audit logs.
* `AuditService.java` (Java, 45 LOC) — Service for recording audit log events asynchronously.

#### Authentication & Users (`com.blueops.auth` & `com.blueops.users`) (10 Files)
* `AuthController.java` (Java, 65 LOC) — Login, refresh, logout, and current user profile endpoints.
* `AuthService.java` (Java, 92 LOC) — User credential validation and JWT issuance service.
* `LoginRateLimiter.java` (Java, 58 LOC) — In-memory sliding-window IP brute force protection.
* `LoginRequest.java` (Java, 22 LOC) — Login credentials request payload DTO.
* `LoginResponse.java` (Java, 32 LOC) — JWT tokens and user profile response DTO.
* `RefreshTokenRequest.java` (Java, 18 LOC) — Token refresh payload DTO.
* `UserDto.java` (Java, 28 LOC) — User account representation DTO.
* `User.java` (Java, 62 LOC) — JPA entity representing SOC users and roles.
* `UserRepository.java` (Java, 18 LOC) — Spring Data JPA repository for users.
* `UserService.java` (Java, 45 LOC) — User lookup and password management.

#### Detections & Correlation (`com.blueops.detections`) (6 Files)
* `DetectionRule.java` (Java, 75 LOC) — JPA entity for detection rule metadata and status.
* `DetectionRuleController.java` (Java, 62 LOC) — Rule catalog endpoints and status toggle.
* `DetectionRuleDto.java` (Java, 48 LOC) — Detection rule transfer object.
* `DetectionRuleRepository.java` (Java, 22 LOC) — Spring Data JPA repository for detection rules.
* `DetectionRuleService.java` (Java, 85 LOC) — Rule management and coverage aggregation service.
* `correlation/CorrelationEngine.java` (Java, 142 LOC) — Sliding-window multi-stage correlation engine (C001–C004).

#### Findings & OpenSearch (`com.blueops.findings`) (3 Files)
* `FindingController.java` (Java, 45 LOC) — Endpoints for querying security findings.
* `FindingDto.java` (Java, 68 LOC) — Security finding record with MITRE technique mappings.
* `OpenSearchFindingAdapter.java` (Java, 155 LOC) — OpenSearch cluster adapter with resilient in-memory fallback.

#### Incident Management (`com.blueops.incidents`) (13 Files)
* `Incident.java` (Java, 95 LOC) — Master JPA entity representing SOC security incidents.
* `IncidentController.java` (Java, 115 LOC) — Complete incident triage, assignment, note, and reopen endpoints.
* `IncidentDto.java` (Java, 78 LOC) — Full incident transfer object.
* `IncidentFinding.java` (Java, 42 LOC) — Association entity linking incidents to OpenSearch findings.
* `IncidentNote.java` (Java, 45 LOC) — Analyst chronological investigation notes entity.
* `IncidentRepository.java` (Java, 25 LOC) — Spring Data JPA repository for incidents.
* `IncidentService.java` (Java, 185 LOC) — Incident business logic and state progression.
* `IncidentSeverity.java` (Java, 14 LOC) — Severity enum (LOW, MEDIUM, HIGH, CRITICAL).
* `IncidentStatus.java` (Java, 15 LOC) — Lifecycle status enum (NEW, TRIAGED, INVESTIGATING, CONTAINED, CLOSED).
* `IncidentStatusHistory.java` (Java, 48 LOC) — Historical record of status changes for auditability.
* `IncidentStateMachine.java` (Java, 55 LOC) — Formal lifecycle transition validator.
* `IncidentTimelineEntryDto.java` (Java, 42 LOC) — Chronological timeline view DTO.
* `IncidentCreateRequest.java` / `IncidentAssignRequest.java` / `IncidentNoteRequest.java` (Java, 60 LOC).

#### Reporting & Analytics (`com.blueops.reporting`) (3 Files)
* `ReportingController.java` (Java, 42 LOC) — Endpoints for SOC health and ATT&CK coverage metrics.
* `ReportingService.java` (Java, 95 LOC) — Aggregation engine calculating MTTD, MTTR, and coverage.
* `SocOverviewMetricsDto.java` (Java, 55 LOC) — Operational metrics summary DTO.

#### SOAR & Active Response (`com.blueops.response`) (7 Files)
* `ResponseController.java` (Java, 85 LOC) — Playbook catalog and action execution/approval endpoints.
* `ResponseService.java` (Java, 165 LOC) — Human-in-the-loop orchestration and compensating rollback logic.
* `ResponseAction.java` (Java, 88 LOC) — JPA entity recording remediation action requests and states.
* `ResponseActionDto.java` (Java, 58 LOC) — Response action representation DTO.
* `ResponsePlaybook.java` (Java, 62 LOC) — Playbook template definition entity.
* `HmacSignatureService.java` (Java, 68 LOC) — HMAC-SHA256 signer and constant-time verifier.
* `ResponseActionRepository.java` (Java, 20 LOC) — Spring Data JPA repository for response actions.

#### Security & Filters (`com.blueops.security`) (6 Files)
* `SecurityConfig.java` (Java, 85 LOC) — Spring Security filter chain, stateless session, and RBAC rules.
* `JwtAuthenticationFilter.java` (Java, 65 LOC) — Per-request Bearer token extractor and security context loader.
* `JwtTokenProvider.java` (Java, 98 LOC) — JJWT token generator, claim parser, and expiration checker.
* `UserDetailsServiceImpl.java` (Java, 42 LOC) — Spring Security user details provider.
* `UserPrincipal.java` (Java, 65 LOC) — Authenticated user principal wrapper.
* `JwtAuthenticationEntryPoint.java` (Java, 32 LOC) — Rejection handler for unauthenticated requests.

#### Telemetry Pipeline (`com.blueops.telemetry`) (8 Files)
* `TelemetryController.java` (Java, 75 LOC) — REST ingestion, recent event query, DLQ, and stats endpoints.
* `TelemetryService.java` (Java, 92 LOC) — Pipeline coordinator for ingestion, normalization, and detection.
* `EventNormalizationService.java` (Java, 210 LOC) — Standardizes Sysmon, Auditd, Suricata into CES v1.0.0.
* `DetectionEvaluationService.java` (Java, 385 LOC) — Evaluates 18 single-event rules (D001–D018) and IOC matches.
* `NormalizedEvent.java` (Java, 145 LOC) — Structured POJO representation of the Common Event Schema.
* `TelemetryIngestRequest.java` (Java, 30 LOC) — Ingestion wrapper DTO.
* `TelemetryStatsDto.java` (Java, 35 LOC) — Operational throughput and DLQ metrics DTO.
* `SimulateAttackRequest.java` (Java, 25 LOC) — Synthetic attack simulation trigger DTO.

#### Common & Exceptions (`com.blueops.common`) (6 Files)
* `ApiResponse.java` (Java, 42 LOC) — Standardized JSON envelope wrapper for all REST responses.
* `PagedResponse.java` (Java, 48 LOC) — Generic pagination wrapper.
* `GlobalExceptionHandler.java` (Java, 78 LOC) — Centralized exception handler (`@RestControllerAdvice`).
* `ResourceNotFoundException.java` (Java, 22 LOC) — HTTP 404 domain exception.
* `InvalidActionException.java` (Java, 20 LOC) — HTTP 400 state transition exception.
* `UnauthorizedException.java` (Java, 20 LOC) — HTTP 401 authorization exception.

#### Backend Resources & Database Migrations (5 Files)
* `backend/src/main/resources/application.yml` (YAML, 75 LOC) — Configuration for server, database, JWT, OpenSearch.
* `backend/src/main/resources/application-test.yml` (YAML, 35 LOC) — Test profile configuration utilizing H2.
* `backend/src/main/resources/db/migration/V1__initial_schema.sql` (SQL, 145 LOC) — DDL creating all 10 core tables.
* `backend/src/main/resources/db/migration/V2__seed_initial_data.sql` (SQL, 120 LOC) — DML seeding baseline rules, users, IOCs.

#### Backend Automated Test Suite (8 Files)
* `IncidentAdvisoryServiceTest.java` (Java, 95 LOC) — 3 tests for regulatory recommendations.
* `CorrelationEngineTest.java` (Java, 115 LOC) — 4 tests for multi-stage correlation scenarios (C001–C004).
* `TelemetryNormalizationAndDetectionTest.java` (Java, 265 LOC) — 15 tests for normalization and rules D001–D018.
* `IncidentServiceTest.java` (Java, 95 LOC) — 4 tests for incident lifecycle and notes.
* `IncidentStateMachineTest.java` (Java, 65 LOC) — 2 tests for state transitions and invalid actions.
* `HmacSignatureServiceTest.java` (Java, 55 LOC) — 2 tests for HMAC-SHA256 signing and tampering detection.
* `JwtTokenProviderTest.java` (Java, 62 LOC) — 2 tests for JWT generation, validation, and malformed rejection.
* `LoginRateLimiterTest.java` (Java, 48 LOC) — 2 tests for sliding-window IP brute force rate limiting.

---

### 2.3. Frontend Presentation Tier (React 18 / TypeScript / Vite) (36 Files)

#### Application Core & Navigation (4 Files)
* `frontend/src/App.tsx` (TSX, 195 LOC) — Master application shell, stateful tab routing, modal controllers.
* `frontend/src/main.tsx` (TSX, 22 LOC) — React root mounting point with StrictMode.
* `frontend/src/index.css` (CSS, 45 LOC) — Global Tailwind styles and custom dark-theme scrollbars.
* `frontend/index.html` (HTML, 28 LOC) — Master HTML entry point.

#### Page Views (11 Files)
* `OverviewPage.tsx` (TSX, 315 LOC) — SOC dashboard with metrics, Recharts charts, alert summary.
* `IncidentCenterPage.tsx` (TSX, 285 LOC) — Filterable incident table with severity and triage controls.
* `InvestigationWorkspacePage.tsx` (TSX, 420 LOC) — Detailed investigation view with timeline, findings, notes.
* `AdversaryConsolePage.tsx` (TSX, 260 LOC) — Atomic Red Team attack simulation trigger panel.
* `LiveTelemetryPage.tsx` (TSX, 290 LOC) — Real-time event streaming table and DLQ inspector.
* `DetectionManagementPage.tsx` (TSX, 245 LOC) — Sigma rule catalog and status toggle panel.
* `ResponseManagementPage.tsx` (TSX, 280 LOC) — Playbook catalog, pending approval cards, rollback triggers.
* `ThreatIntelPage.tsx` (TSX, 265 LOC) — IOC search, confidence visualization, JSON import modal.
* `AssetInventoryPage.tsx` (TSX, 240 LOC) — Monitored host cards, IP/OS details, isolation badges.
* `AuditReportsPage.tsx` (TSX, 210 LOC) — Administrative compliance audit trail table.
* `LoginPage.tsx` (TSX, 165 LOC) — Split-panel cybersecurity login screen with credential helpers.

#### Reusable Components (6 Files)
* `AuthoritativeAdvisor.tsx` (TSX, 245 LOC) — Recommendation cards with NIST/CISA badges and 1-click execution.
* `Header.tsx` (TSX, 115 LOC) — Top navigation bar with live health pill, active incident counter, user profile.
* `Sidebar.tsx` (TSX, 135 LOC) — Collapsible navigation sidebar with category dividers.
* `SeverityBadge.tsx` (TSX, 42 LOC) — Color-coded severity badge (Critical, High, Medium, Low).
* `StatusBadge.tsx` (TSX, 48 LOC) — Incident lifecycle status badge (New, Triaged, Contained, Closed).
* `AdversaryConsole.test.tsx` / `AuthoritativeAdvisor.test.tsx` / `SeverityBadge.test.tsx` (TSX, 190 LOC).

#### Context, Services, Types & Configuration (15 Files)
* `AuthContext.tsx` (TSX, 115 LOC) — Global authentication state provider with auto-refresh logic.
* `services/api.ts` (TS, 145 LOC) — Axios client with JWT Bearer interceptor and error handlers.
* `types/index.ts` (TS, 185 LOC) — TypeScript interface definitions for all domain models.
* `vite.config.ts` / `tsconfig.json` / `tailwind.config.js` / `postcss.config.js` / `package.json` (Configs).

---

### 2.4. Detection Rules: Sigma Specifications (19 Files)
* `detection-rules/README.md` (Markdown, 55 LOC) — Sigma rule naming, severity standards, and ATT&CK alignment.
* 18 Sigma YAML rule definitions in `linux/`, `windows/`, and `network/` (D001 through D018).

---

### 2.5. Infrastructure, Ingestion & Response Agent (16 Files)
* `infrastructure/fluent-bit/fluent-bit.conf` (Config, 68 LOC) — Log forwarder pipeline configuration.
* `infrastructure/fluent-bit/parsers.conf` (Config, 38 LOC) — Parsers for Suricata EVE and Syslog.
* `infrastructure/opensearch/index-templates/*.json` (3 files, 185 LOC) — Templates for events, findings, DLQ.
* `infrastructure/windows/sysmon-config.xml` (XML, 145 LOC) — Sysmon endpoint collection schema.
* `infrastructure/linux/audit-rules/audit.rules` (Config, 65 LOC) — Linux kernel auditd rule definitions.
* `infrastructure/suricata/suricata.yaml` & `blueops-lab.rules` (Config, 120 LOC) — Suricata IDS configuration.
* `response-agent/src/agent.py` (Python, 175 LOC) — HMAC-authenticated restricted response agent.
* `response-agent/tests/test_agent.py` (Python, 85 LOC) — Pytest suite verifying agent boundaries.
* `docker-compose.yml` & `docker-compose.override.yml` (YAML, 185 LOC) — 7-container Docker Compose mesh.

---

### 2.6. Test Lab & BAS Simulation Suite (7 Files)
* `test-lab/run_simulations.js` (JavaScript, 265 LOC) — 60-scenario automated benchmark runner.
* `test-lab/adversary-simulation/deceptive_attack_suite.js` (JavaScript, 245 LOC) — Evasion testing suite.
* `test-lab/scenarios/test_scenarios.json` (JSON, 285 LOC) — Declarative attack telemetry payloads.
* `test-lab/results/benchmark_report.json` & `deceptive_attack_report.json` (JSON, 380 LOC) — Benchmark reports.
* `start.bat` / `start.sh` / `test.bat` / `test.sh` (Shell & Batch, 120 LOC) — Operational lifecycle scripts.
