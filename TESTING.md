# BlueOps Testing Architecture & Empirical Evaluation Baseline

**Document ID:** BLUEOPS-TEST-001  
**Classification:** Quality Assurance, Test Suite Specifications & Benchmark Standards  
**Version:** 1.0.0  
**Status:** Living Engineering Standard  

---

## 1. Testing Architecture Overview

BlueOps enforces an evidence-based testing methodology with strict non-destructive isolation:
1. **Backend Unit & Integration Tests (JUnit 5 + Spring Boot Test):** Unit coverage for normalization, rule evaluation, token security, and correlation.
2. **Frontend Component & Unit Tests (Vitest + React Testing Library):** UI state, rendering, role gating, and error boundaries.
3. **Frontend Production Build Verification (`tsc && vite build`):** Strict TypeScript type checking across all views and API models.
4. **Adversary Simulation Benchmark (`test-lab/run_simulations.js`):** Empirical dynamic evaluation against 10 Atomic Red Team attack scenarios and 50 benign enterprise baseline telemetry streams.
5. **Deceptive Attack & Anti-Tamper Suite (`test-lab/adversary-simulation/deceptive_attack_suite.js`):** 8 evasive attack vectors and 5 boundary security tests for the Python response agent.

---

## 2. Empirical Verification Baseline

As of **November 20, 2026**, the system exhibits the following baseline test results:

### 2.1. Backend JUnit 5 Suite
- **Command:** `cd backend && .\mvnw.cmd test`
- **Execution Time:** ~41.7 seconds
- **Results:**
  - **Total Tests Run:** 40
  - **Passed:** 40 (100%)
  - **Failures:** 0
  - **Errors:** 0
  - **Skipped:** 0
- **Key Test Classes:**
  - `TelemetryNormalizationAndDetectionTest`: 15 tests covering Sysmon EventIDs 1, 3, 10, 11, Linux auditd SYSCALL, Suricata 5-tuples, DLQ routing, and rules D001–D018.
  - `SecurityStartupValidatorTest`: 4 tests validating length bounds, weak key rejection in `prod`, and dev fallbacks.
  - `SigmaRuleParserAndRegistryTest`: 3 tests validating SnakeYAML parsing across all 18 production Sigma YAML rules.
  - `AuthoritativeAdvisorTest`: 5 tests verifying playbook generation and risk ranking.
  - `JwtTokenProviderTest` & `AuthServiceTest`: 8 tests validating JWT lifecycle and credential handling.
  - `AssetServiceTest` & `AuditServiceTest`: 5 tests validating asset risk calculation and audit trail creation.

### 2.2. Frontend Vitest Suite
- **Command:** `cd frontend && npm.cmd test`
- **Execution Time:** ~30.0 seconds
- **Results:**
  - **Test Files Passed:** 3 / 3
  - **Total Tests Run:** 6
  - **Passed:** 6 (100%)
  - **Failures:** 0
- **Coverage:**
  - `SeverityBadge.test.tsx` (2 tests)
  - `AdversaryConsole.test.tsx` (1 test)
  - `AuthoritativeAdvisor.test.tsx` (3 tests)

### 2.3. Frontend TypeScript & Production Build
- **Command:** `cd frontend && npm.cmd run build`
- **Execution Time:** ~14.16 seconds
- **Result:** **0 TypeScript errors**, 1,589 modules transformed cleanly.

### 2.4. Adversary Simulation Benchmark (Dynamic Evaluation)
- **Command:** `node test-lab/run_simulations.js`
- **Metrics Summary:**
  - **Adversary Scenarios Evaluated:** 10
  - **Benign Baselines Evaluated:** 50
  - **True Positives (TP):** 10 / 10
  - **False Positives (FP):** 0
  - **True Negatives (TN):** 50 / 50
  - **False Negatives (FN):** 0
  - **Precision:** 100.00%
  - **Recall (Sensitivity):** 100.00%
  - **Specificity:** 100.00%
  - **False Positive Rate (FPR):** 0.0000%
  - **F1-Score:** 1.0000
  - **Overall Accuracy:** 100.00%
  - **Mean Time to Detect (MTTD):** 3.33 seconds
  - **Mean Time to Respond (MTTR):** 42.50 seconds

### 2.5. Deceptive Attack & Response Boundary Evaluation
- **Command:** `node test-lab/adversary-simulation/deceptive_attack_suite.js`
- **Adversary Detection Results (8 Advanced Scenarios):**
  - ATK-001: Deceptive Encoded PowerShell (Mixed Case `-eNCoDeDCoMmAnD`) -> **DETECTED** (D008)
  - ATK-002: Office Macro Spawning Command Interpreter -> **DETECTED** (D008, D009)
  - ATK-003: In-Memory LSASS MiniDump via `comsvcs.dll` -> **DETECTED** (D011)
  - ATK-004: Windows Event Log Clearing via `wevtutil` -> **DETECTED** (D013)
  - ATK-005: Linux Audit Subsystem Tampering via `auditctl` -> **DETECTED** (D006)
  - ATK-006: Linux Interactive Root Shell Escalation -> **DETECTED** (D004)
  - ATK-007: Outbound C2 Egress to Threat Intel Indicator -> **DETECTED** (D015)
  - ATK-008: Process Masquerading as `svchost.exe` outside `system32` -> **DETECTED** (D018)
  - **Detection Rate:** 8 / 8 (100.00%)
- **Response Agent Security Boundary Defense (5 Tests):**
  - Replay Defense (Expired Timestamp > 60s): **PASS** (`REJECTED_EXPIRED`)
  - HMAC Tamper Defense (Forged / Invalid Signature): **PASS** (`REJECTED_INVALID_SIG`)
  - Command Injection Defense (Semicolon / Shell Injection): **PASS** (`REJECTED_INVALID_PARAMETER`)
  - Unauthorized Action Defense (Action Not Allowlisted): **PASS** (`REJECTED_UNAUTHORIZED_ACTION`)
  - Legitimate Authorized Action (Valid HMAC & Window): **PASS** (`ACCEPTED_EXECUTED`)
  - **Boundary Pass Rate:** 5 / 5 (100.00%)

---

## 3. Safe Execution Protocol

- **Synthetic Telemetry Only:** All tests operate exclusively on synthetic, benign event streams.
- **Simulation Driver Isolation:** Pytest and integration tests against `response-agent` must run with `EXECUTION_MODE=SIMULATION`.
- **Zero Real System Changes:** Under no circumstances should test suites execute unapproved firewall rule additions, system file modifications, or account changes against the host operating system.
