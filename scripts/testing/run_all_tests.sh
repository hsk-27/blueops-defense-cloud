#!/usr/bin/env bash
# BlueOps - Universal Test Runner (Linux / macOS)
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT_DIR"

echo "============================================================"
echo "          BlueOps Universal Test Suite Execution            "
echo "============================================================"

# 1. Backend Tests
echo "[1/4] Running Backend JUnit 5 Tests..."
cd "$ROOT_DIR/backend"
chmod +x ./mvnw
./mvnw -B test

# 2. Frontend Tests & Build
echo "[2/4] Running Frontend Vitest Suite & Production Build..."
cd "$ROOT_DIR/frontend"
npm test
npm run build

# 3. Dynamic Empirical Benchmark
echo "[3/4] Running Dynamic Empirical Research Benchmark..."
cd "$ROOT_DIR"
node test-lab/run_simulations.js

# 4. Deceptive Adversary Simulation Suite
echo "[4/4] Running Deceptive Adversary Simulation Suite..."
node test-lab/adversary-simulation/deceptive_attack_suite.js

echo ""
echo "============================================================"
echo "    [+] ALL BLUEOPS TEST SUITES COMPLETED SUCCESSFULLY      "
echo "============================================================"
