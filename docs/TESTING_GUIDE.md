# BlueOps — Verification & Testing Guide

> **Notice:** For step-by-step hands-on procedures to manually simulate attacks, test rate limiters, trigger correlation chains, and audit the response agent boundary, consult the [**Comprehensive Manual Testing Runbook**](MANUAL_TESTING_GUIDE.md).

## 1. Automated Test Execution

### 1.1 Backend Unit & Integration Tests (32 / 32 Passing)
Runs JUnit 5 test suite verifying JWT issuance, incident state machine transitions, correlation scenarios, download cradles, case-insensitive threat intel matching, and HMAC cryptography:
```bash
cd backend
./mvnw test
```

### 1.2 Frontend Unit Tests (6 / 6 Passing)
Runs Vitest test suite verifying badge rendering, UI state, clipboard SOP export, and component integrity:
```bash
cd frontend
npm test
```

### 1.3 Restricted Response Agent Tests
Runs Pytest verifying signature parsing, expiration thresholds, and replay attacks:
```bash
cd response-agent
pytest tests/
```

---

## 2. Controlled Adversary Benchmark Execution
Executes the reproducible Atomic Red Team validation suite against the 10 test scenarios and 50 benign baselines:
```bash
node test-lab/run_simulations.js
```

Outputs performance metrics:
- Precision: $\frac{TP}{TP + FP}$
- Recall: $\frac{TP}{TP + FN}$
- False Positive Rate: $\frac{FP}{FP + TN}$
- Specificity: $\frac{TN}{TN + FP}$
- MTTD (Mean Time to Detect)
- MTTR (Mean Time to Respond)

Results are automatically saved to `test-lab/results/benchmark_report.json`.

---

## 3. Deceptive Adversary Simulation Suite (8 / 8 Detected, 5 / 5 Boundary Defenses)
Executes advanced obfuscated attacks (LOLBAS, DLL abuse, audit tampering) and tests response agent anti-tamper boundaries:
```bash
node test-lab/adversary-simulation/deceptive_attack_suite.js
```

Results are saved to `test-lab/results/deceptive_attack_report.json`.

---

## 4. Universal Single-Command Test Runner
Execute all automated suites in sequence with a single script:
- **Windows:** `.\test.bat`
- **Linux / macOS:** `./test.sh`
