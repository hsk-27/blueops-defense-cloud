# BlueOps — Controlled Adversary Simulation Guide

## 1. Simulation Principles
All tests are performed in strictly isolated lab virtual machines or network segments.
Adversary simulations utilize **Atomic Red Team** atomic tests to generate authentic endpoint and network telemetry without causing destructive damage.

---

## 2. Test Scenarios (T001 to T010)

### T001 — SSH Brute-Force Simulation
- **Target:** `LAB-LNX-01` (Ubuntu 22.04, `192.168.56.102`)
- **MITRE ATT&CK:** T1110.001 (Password Guessing)
- **Execution:** Rapid failed SSH authentications from simulated adversary IP `198.51.100.24`.
- **Expected Finding:** `D001` (Repeated SSH Authentication Failures).

### T002 — Successful SSH Login Following Failures
- **Target:** `LAB-LNX-01`
- **MITRE ATT&CK:** T1110 (Brute Force)
- **Expected Correlation:** `C001` (Linux Account Compromise Sequence).

### T003 — Linux Privilege Escalation
- **Target:** `LAB-LNX-01`
- **MITRE ATT&CK:** T1548.003 (Sudo and Sudo Caching)
- **Expected Finding:** `D004` (Unexpected Privileged Command Execution).

### T004 — Linux User Creation & Persistence
- **Target:** `LAB-LNX-01`
- **MITRE ATT&CK:** T1136.001 (Local Account)
- **Expected Finding:** `D005` (Privileged Account Creation).

### T005 — Windows Suspicious PowerShell Execution
- **Target:** `LAB-WIN-01` (Windows 11, `192.168.56.101`)
- **MITRE ATT&CK:** T1059.001 (PowerShell)
- **Execution:** Invocation with `-EncodedCommand` and `-ExecutionPolicy Bypass`.
- **Expected Finding:** `D008` (Suspicious PowerShell Execution).

### T006 — Suspicious Process Chain
- **Target:** `LAB-WIN-01`
- **MITRE ATT&CK:** T1059 (Command and Scripting Interpreter)
- **Execution:** Word / Office process spawning `cmd.exe` or `powershell.exe`.
- **Expected Correlation:** `C002` (Windows Multi-Stage Execution Chain).

### T007 — Scheduled Task Creation
- **Target:** `LAB-WIN-01`
- **MITRE ATT&CK:** T1053.005 (Scheduled Task)
- **Expected Finding:** `D010` (Unexpected Scheduled Task Creation).

### T008 — Security Event Log Clearing
- **Target:** `LAB-WIN-01`
- **MITRE ATT&CK:** T1070.001 (Clear Windows Event Logs)
- **Expected Finding:** `D013` (Security Event Log Clearing).

### T009 — Known Threat Intel IOC Communication
- **Target:** `LAB-FW-01` (Suricata NIDS)
- **MITRE ATT&CK:** T1071 (Application Layer Protocol)
- **Execution:** Outbound connection to `evil-corp.blueops.lab` or `198.51.100.24`.
- **Expected Finding:** `D015` (Known IOC Communication).

### T010 — Controlled Response Simulation
- **Target:** `LAB-WIN-01` / `LAB-LNX-01`
- **Execution:** Launch Playbook `P001` (Block Lab IP) or `P003` (Isolate Endpoint).
- **Verification:** Verification status recorded; rollback verified.
