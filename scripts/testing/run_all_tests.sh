#!/usr/bin/env bash
# BlueOps - Universal Test Runner (Linux / macOS)
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT_DIR"

echo "============================================================"
echo "          BlueOps Universal Test Suite Execution            "
echo "============================================================"

# 1. Backend Tests
echo "[1/5] Running Backend JUnit 5 Tests..."
cd "$ROOT_DIR/backend"
chmod +x ./mvnw
./mvnw -B test

# 2. Frontend Tests & Build
echo "[2/5] Running Frontend Vitest Suite & Production Build..."
cd "$ROOT_DIR/frontend"
npm test -- --run
npm run build

# 3. Response Agent Contract Tests
echo "[3/5] Running Response Agent Contract Tests..."
cd "$ROOT_DIR/response-agent"
python3 -m pytest -q

# 4. Standalone JS Rule-Logic Smoke Check
echo "[4/5] Running Standalone JS Rule-Logic Smoke Check..."
cd "$ROOT_DIR"
node test-lab/run_simulations.js

# 5. Deceptive Adversary Simulation Suite
echo "[5/5] Running Deceptive Adversary Simulation Suite..."
node test-lab/adversary-simulation/deceptive_attack_suite.js

echo ""
echo "============================================================"
echo "    [+] ALL BLUEOPS TEST SUITES COMPLETED SUCCESSFULLY      "
echo "============================================================"
