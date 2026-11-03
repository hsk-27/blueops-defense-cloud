# BlueOps - Telemetry Pipeline Verification Script (Windows PowerShell)
$BackendUrl = if ($env:BLUEOPS_BACKEND_URL) { $env:BLUEOPS_BACKEND_URL } else { "http://localhost:8080" }
Write-Host "[*] Verifying BlueOps Backend connectivity at: $BackendUrl" -ForegroundColor Cyan

# Health Check
try {
    $health = Invoke-RestMethod -Uri "$BackendUrl/actuator/health" -Method Get -TimeoutSec 5
    Write-Host "[+] Backend Health: $($health.status)" -ForegroundColor Green
} catch {
    Write-Host "[-] Backend Health: OFFLINE or UNREACHABLE ($($_.Exception.Message))" -ForegroundColor Red
}

# Verification of sample Sysmon ingestion
Write-Host "[*] Sending sample verification telemetry payload..." -ForegroundColor Cyan
$samplePayload = @{
    provider = "Sysmon"
    EventID = 1
    hostname = "WIN-TEST-01"
    CommandLine = "whoami.exe"
    user = "analyst"
} | ConvertTo-Json

try {
    $response = Invoke-RestMethod -Uri "$BackendUrl/api/v1/telemetry/ingest" -Method Post -Body $samplePayload -ContentType "application/json" -TimeoutSec 5
    Write-Host "[+] Telemetry Pipeline: INGESTION SUCCESSFUL" -ForegroundColor Green
} catch {
    Write-Host "[-] Telemetry Pipeline: INGESTION FAILED ($($_.Exception.Message))" -ForegroundColor Red
}
