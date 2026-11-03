# BlueOps - Local Environment Initialization Script (Windows PowerShell)
$ErrorActionPreference = "Stop"

Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "    BlueOps SOC Platform - Environment Initialization       " -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan

# 1. Environment file check
if (-not (Test-Path ".env")) {
    Write-Host "[*] Creating .env from .env.example..." -ForegroundColor Yellow
    Copy-Item ".env.example" ".env"
} else {
    Write-Host "[+] Existing .env file detected." -ForegroundColor Green
}

# 2. Check Docker
if (Get-Command docker -ErrorAction SilentlyContinue) {
    $dockerVer = docker --version
    Write-Host "[+] Docker detected: $dockerVer" -ForegroundColor Green
} else {
    Write-Host "[-] Warning: Docker not found. Container infrastructure cannot be started automatically." -ForegroundColor DarkYellow
}

# 3. Check Java
if (Get-Command java -ErrorAction SilentlyContinue) {
    $javaVer = java -version 2>&1 | Select-Object -First 1
    Write-Host "[+] Java detected: $javaVer" -ForegroundColor Green
} else {
    Write-Host "[-] Warning: Java not detected. JDK 21+ is required for the backend." -ForegroundColor DarkYellow
}

# 4. Check Node.js
if (Get-Command node -ErrorAction SilentlyContinue) {
    $nodeVer = node --version
    Write-Host "[+] Node.js detected: $nodeVer" -ForegroundColor Green
} else {
    Write-Host "[-] Warning: Node.js not detected. Node 20+ is required for frontend and simulation harness." -ForegroundColor DarkYellow
}

Write-Host ""
Write-Host "[+] Initialization complete. You can now start infrastructure via:" -ForegroundColor Cyan
Write-Host "    docker compose up -d postgres opensearch opensearch-dashboards fluent-bit" -ForegroundColor White
Write-Host "============================================================" -ForegroundColor Cyan
