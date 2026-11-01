# BlueOps — Verification & Testing Guide

## 1. Automated Test Execution

### 1.1 Backend Unit & Integration Tests
Runs JUnit 5 test suite verifying JWT issuance, incident state machine transitions, correlation scenarios, and HMAC cryptography:
```bash
cd backend
./mvnw test
```

### 1.2 Frontend Unit Tests
Runs Vitest test suite verifying badge rendering, UI state, and component integrity:
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
Executes the reproducible Atomic Red Team validation suite against the 10 test scenarios:
```bash
node test-lab/run_simulations.js
```

Outputs performance metrics:
- Precision: $\frac{TP}{TP + FP}$
- Recall: $\frac{TP}{TP + FN}$
- False Positive Rate: $\frac{FP}{FP + TN}$
- MTTD (Mean Time to Detect)
- MTTR (Mean Time to Respond)

Results are automatically saved to `test-lab/results/benchmark_report.json`.
