# BlueOps - Universal Test Runner (Windows PowerShell)
$ErrorActionPreference = "Stop"

$RootDir = Resolve-Path "$PSScriptRoot\..\.."
Set-Location $RootDir

Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "          BlueOps Universal Test Suite Execution            " -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan

# 1. Backend Tests
Write-Host "[1/4] Running Backend JUnit 5 Tests..." -ForegroundColor Yellow
Set-Location "$RootDir\backend"
.\mvnw.cmd -o test

# 2. Frontend Tests & Build
Write-Host "[2/4] Running Frontend Vitest Suite & Production Build..." -ForegroundColor Yellow
Set-Location "$RootDir\frontend"
node node_modules\vitest\vitest.mjs run
node node_modules\vite\bin\vite.js build

# 3. Dynamic Empirical Benchmark
Write-Host "[3/4] Running Dynamic Empirical Research Benchmark..." -ForegroundColor Yellow
Set-Location $RootDir
node test-lab\run_simulations.js

# 4. Deceptive Adversary Simulation Suite
Write-Host "[4/4] Running Deceptive Adversary Simulation Suite..." -ForegroundColor Yellow
node test-lab\adversary-simulation\deceptive_attack_suite.js

Write-Host ""
Write-Host "============================================================" -ForegroundColor Green
Write-Host "    [+] ALL BLUEOPS TEST SUITES COMPLETED SUCCESSFULLY      " -ForegroundColor Green
Write-Host "============================================================" -ForegroundColor Green
