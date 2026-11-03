# BlueOps — Testing & Quality Assurance Audit Report

This report provides a comprehensive audit of all automated test suites across the BlueOps platform.

---

## 1. Test Suite Summary Table

| Test Suite | Framework / Tool | Location | Total Tests | Passed | Failed | Execution Time |
|---|---|---|:---:|:---:|:---:|:---:|
| **Backend Unit Tests** | JUnit 5 + Mockito | `backend/src/test/` | 22 | 22 | 0 | 23.33s |
| **Frontend Unit Tests** | Vitest + Testing Library | `frontend/src/tests/` | 3 | 3 | 0 | 24.92s |
| **Frontend Production Build** | Vite v5.4.21 | `frontend/` | 1588 modules | SUCCESS | 0 | 15.98s |
| **Adversary Attack Suite** | Node.js | `test-lab/adversary-simulation/` | 8 | 8 | 0 | 2.10s |
| **Response Boundary Defense** | Node.js | `test-lab/adversary-simulation/` | 5 | 5 | 0 | 0.80s |
| **Dynamic Empirical Benchmark** | Node.js (Atomic Red Team) | `test-lab/run_simulations.js` | 60 | 60 | 0 | 3.80s |
| **TOTAL** | | | **98** | **98** | **0** | **100% Pass** |

---

## 2. Backend Unit Test Suite Details (`backend/src/test/`)

Run Command: `cd backend; .\mvnw.cmd -o test`

### 2.1 `LoginRateLimiterTest.java` (2 Tests)
- `shouldLockOutAccountAfterExceedingFailureThreshold`: Simulates 5 consecutive failed login attempts. Asserts that the 6th attempt is locked out with remaining lockout time > 0.
- `shouldResetFailureCountOnSuccessfulLogin`: Simulates 3 failures followed by a successful login. Asserts that the counter is reset and subsequent attempts are permitted.

### 2.2 `TelemetryNormalizationAndDetectionTest.java` (12 Tests)
- `shouldNormalizeSysmonTelemetry`: Verifies Sysmon Event ID 1 normalization into ECS format.
- `shouldDetectEncodedPowerShell`: Verifies rule `D008` fires on `-enc` base64 command lines.
- `shouldDetectOfficeSpawningCommandInterpreter`: Verifies rule `D009` fires on `WINWORD.EXE` spawning `cmd.exe`.
- `shouldDetectMimikatzLsassDump`: Verifies rule `D011` fires on `comsvcs.dll MiniDump`.
- `shouldDetectThreatIntelIocMatch`: Verifies rule `D015` fires on known threat intel IP indicator `198.51.100.24`.
- `shouldProduceNoFindingsOnBenignActivity`: Verifies benign `notepad.exe` produces 0 findings.
- `shouldDetectSystemdServiceCreation`: Verifies rule `D007` fires on `/etc/systemd/system/backdoor.service`.
- `shouldDetectDriverLoading`: Verifies rule `D012` fires on unexpected `.sys` kernel driver loading.
- `shouldDetectEventLogClearing`: Verifies rule `D013` fires on `wevtutil cl Security`.
- `shouldDetectProtectedFileModification`: Verifies rule `D016` fires on `drivers\etc\hosts` file modification.
- `shouldDetectRepeatedAuthenticationFailures`: Verifies rule `D017` fires on repeated failed logins from a single source.
- `shouldDetectUnusualAdministrativeServiceCreation`: Verifies rule `D018` fires on `sc.exe create` service installation.

### 2.3 `CorrelationEngineTest.java` (2 Tests)
- `shouldCorrelateLinuxBruteForceSequence`: Verifies D001 + D002 generates correlated scenario `C001`.
- `shouldCorrelateWindowsMultiStageExecution`: Verifies D009 + D008 generates correlated scenario `C002`.

### 2.4 `IncidentStateMachineTest.java` (2 Tests)
- `shouldEnforceValidStateTransitions`: Validates strict forward transitions (NEW -> TRIAGED -> INVESTIGATING -> CONTAINED -> RESOLVED -> CLOSED).
- `shouldRejectInvalidTransitions`: Asserts that transitioning from NEW directly to CLOSED throws `IllegalStateException`.

### 2.5 `HmacSignatureServiceTest.java` (2 Tests)
- `shouldGenerateValidHmacSignature`: Verifies signature creation matches HMAC-SHA256 standard.
- `shouldVerifyMatchingSignature`: Asserts that tamper detection correctly flags modified payloads.

### 2.6 `JwtTokenProviderTest.java` (2 Tests)
- `shouldGenerateAndValidateJwtToken`: Validates standard token claims and signature parsing.
- `shouldRejectTamperedToken`: Asserts that modified token payloads return false and trigger warning logs.

---

## 3. Frontend Unit & Build Verifications (`frontend/`)

### 3.1 Vitest Unit Tests (`node node_modules/vitest/vitest.mjs run`)
- `SeverityBadge.test.tsx` (2 tests): Verifies proper CSS class binding and color rendering for `CRITICAL`, `HIGH`, `MEDIUM`, and `LOW` severities.
- `AdversaryConsole.test.tsx` (1 test): Verifies interactive attack execution triggering and visual output in the analyst console.

### 3.2 Vite Production Build (`node node_modules/vite/bin/vite.js build`)
- Transformed 1588 TypeScript/JSX modules in 15.98 seconds.
- Output artifacts:
  - `dist/index.html`: 0.78 kB
  - `dist/assets/index-WVQUnVrv.css`: 31.18 kB
  - `dist/assets/index-CgldxHTQ.js`: 268.50 kB

---

## 4. Adversary Simulation & Research Benchmark Verifications

### 4.1 Deceptive Attack Suite (`deceptive_attack_suite.js`)
- Tested 8 advanced evasion scenarios: Obfuscated LOLBAS, Macro execution chains, in-memory LSASS dumping, log clearing, auditctl tampering, interactive root shell spawn, C2 egress, and svchost masquerading.
- **Detection Rate:** 100% (8 / 8 detected).
- **Response Agent Boundary Pass:** 5 / 5 (expired timestamp, invalid HMAC, shell injection target, unauthorized action, and valid execution all behaved according to policy).

### 4.2 Dynamic Empirical Benchmark (`run_simulations.js`)
- Evaluated 10 Atomic Red Team scenarios + 50 benign enterprise activities.
- **True Positives:** 10 / 10
- **False Positives:** 0
- **True Negatives:** 50 / 50
- **False Negatives:** 0
- **Precision:** 100.00%
- **Recall:** 100.00%
- **False Positive Rate:** 0.0000%
- **Mean Time to Detect (MTTD):** 3.29 seconds
- **Mean Time to Respond (MTTR):** 42.50 seconds
