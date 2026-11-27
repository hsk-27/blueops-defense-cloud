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

# Authenticate
$token = $null
$adminUser = if ($env:BLUEOPS_ADMIN_USERNAME) { $env:BLUEOPS_ADMIN_USERNAME } else { "admin" }
$adminPass = if ($env:BLUEOPS_ADMIN_PASSWORD) { $env:BLUEOPS_ADMIN_PASSWORD } else { "Admin@BlueOps2026!" }
try {
    $loginBody = @{ username = $adminUser; password = $adminPass } | ConvertTo-Json
    $auth = Invoke-RestMethod -Uri "$BackendUrl/api/v1/auth/login" -Method Post -Body $loginBody -ContentType "application/json" -TimeoutSec 5
    $token = $auth.data.accessToken
    Write-Host "[+] Authentication: SUCCESSFUL (Access token acquired)" -ForegroundColor Green
} catch {
    Write-Host "[-] Authentication: FAILED ($($_.Exception.Message))" -ForegroundColor Yellow
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

$headers = @{}
if ($token) {
    $headers["Authorization"] = "Bearer $token"
}

try {
    $response = Invoke-RestMethod -Uri "$BackendUrl/api/v1/telemetry/ingest" -Method Post -Headers $headers -Body $samplePayload -ContentType "application/json" -TimeoutSec 5
    Write-Host "[+] Telemetry Pipeline: INGESTION SUCCESSFUL" -ForegroundColor Green
} catch {
    Write-Host "[-] Telemetry Pipeline: INGESTION FAILED ($($_.Exception.Message))" -ForegroundColor Red
}
