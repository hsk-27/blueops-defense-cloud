# BlueOps - Universal Test Runner (Windows PowerShell)
$ErrorActionPreference = "Stop"

$RootDir = Resolve-Path "$PSScriptRoot\..\.."
Set-Location $RootDir

Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "          BlueOps Universal Test Suite Execution            " -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan

# 1. Backend Tests
Write-Host "[1/5] Running Backend JUnit 5 Tests..." -ForegroundColor Yellow
Set-Location "$RootDir\backend"
.\mvnw.cmd -B -o test
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

# 2. Frontend Tests & Build
Write-Host "[2/5] Running Frontend Vitest Suite & Production Build..." -ForegroundColor Yellow
Set-Location "$RootDir\frontend"
node node_modules\vitest\vitest.mjs run
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
node node_modules\vite\bin\vite.js build
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

# 3. Response Agent Pytest Suite (runs with Flask or built-in stdlib fallback)
Write-Host "[3/5] Running Response Agent Contract Tests (Pytest)..." -ForegroundColor Yellow
Set-Location "$RootDir\response-agent"
python -m pytest -q
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

# 4. Dynamic Empirical Benchmark
Write-Host "[4/5] Running Standalone JS Rule-Logic Smoke Check..." -ForegroundColor Yellow
Set-Location $RootDir
node test-lab\run_simulations.js
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

# 5. Deceptive Adversary Simulation Suite
Write-Host "[5/5] Running Deceptive Adversary Simulation Suite..." -ForegroundColor Yellow
node test-lab\adversary-simulation\deceptive_attack_suite.js
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

Write-Host ""
Write-Host "============================================================" -ForegroundColor Green
Write-Host "    [+] ALL BLUEOPS TEST SUITES COMPLETED SUCCESSFULLY      " -ForegroundColor Green
Write-Host "============================================================" -ForegroundColor Green
