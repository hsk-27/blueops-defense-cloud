@echo off
REM BlueOps Local Start Script (Windows)
setlocal

echo ============================================================
echo          BlueOps SOC Platform - Local Startup               
echo ============================================================

cd /d "%~dp0"

if not exist ".env" (
    echo [*] Creating .env from .env.example...
    copy .env.example .env
)

echo [*] Starting Docker infrastructure (PostgreSQL, OpenSearch, Fluent Bit)...
docker compose up -d postgres opensearch opensearch-dashboards fluent-bit

echo [*] Launching Spring Boot backend...
start "BlueOps Backend" cmd /c "cd backend && .\mvnw.cmd spring-boot:run"

echo [*] Launching React frontend...
start "BlueOps Frontend" cmd /c "cd frontend && npm run dev"

echo ============================================================
echo BlueOps is launching:
echo   - Frontend: http://localhost:3000
echo   - Backend API: http://localhost:8080
echo   - Swagger UI: http://localhost:8080/swagger-ui.html
echo   - OpenSearch Dashboards: http://localhost:5601
echo ============================================================
endlocal
