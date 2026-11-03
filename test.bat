@echo off
REM BlueOps Universal Test Execution Script (Windows)
setlocal

echo ============================================================
echo           BlueOps Universal Test Suite Execution            
echo ============================================================

cd /d "%~dp0"

echo [1/4] Running Backend JUnit 5 Tests...
cd backend
call .\mvnw.cmd -o test
if %ERRORLEVEL% NEQ 0 (
    echo [ERROR] Backend tests failed!
    exit /b %ERRORLEVEL%
)

echo [2/4] Running Frontend Vitest Suite ^& Production Build...
cd ..\frontend
call node node_modules\vitest\vitest.mjs run
if %ERRORLEVEL% NEQ 0 (
    echo [ERROR] Frontend unit tests failed!
    exit /b %ERRORLEVEL%
)

call node node_modules\vite\bin\vite.js build
if %ERRORLEVEL% NEQ 0 (
    echo [ERROR] Frontend production build failed!
    exit /b %ERRORLEVEL%
)

echo [3/4] Running Dynamic Empirical Research Benchmark...
cd ..
call node test-lab\run_simulations.js
if %ERRORLEVEL% NEQ 0 (
    echo [ERROR] Empirical benchmark simulation failed!
    exit /b %ERRORLEVEL%
)

echo [4/4] Running Deceptive Adversary Simulation Suite...
call node test-lab\adversary-simulation\deceptive_attack_suite.js
if %ERRORLEVEL% NEQ 0 (
    echo [ERROR] Deceptive adversary suite failed!
    exit /b %ERRORLEVEL%
)

echo ============================================================
echo     [+] ALL BLUEOPS TEST SUITES COMPLETED SUCCESSFULLY      
echo ============================================================
endlocal
