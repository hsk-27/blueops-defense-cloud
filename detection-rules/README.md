# BlueOps Detection Rules & Correlation Scenarios

## 1. Detection Library Overview
BlueOps ships with 18 initial Sigma-compatible detection rules and 4 stateful multi-stage correlation scenarios mapped directly to the **MITRE ATT&CK Matrix**.

| Rule ID | Name | Source | Tactic | Technique | Severity |
|---|---|---|---|---|---|
| **D001** | Repeated SSH Authentication Failures | Linux (auditd/sshd) | Credential Access | T1110.001 | MEDIUM |
| **D002** | Successful SSH Login After Repeated Failures | Linux (auditd/sshd) | Credential Access | T1110 | HIGH |
| **D003** | Linux Password Spraying | Linux (PAM/auth) | Credential Access | T1110.003 | HIGH |
| **D004** | Unexpected Privileged Command Execution | Linux (sudo/auditd) | Privilege Escalation | T1548.003 | HIGH |
| **D005** | Privileged Account Creation | Linux (auditd) | Persistence | T1136.001 | HIGH |
| **D006** | Audit Subsystem Tampering | Linux (auditd) | Defense Evasion | T1562.001 | CRITICAL |
| **D007** | Suspicious Systemd Service Creation | Linux (systemd) | Persistence | T1543.002 | MEDIUM |
| **D008** | Suspicious PowerShell Execution | Windows (Sysmon) | Execution | T1059.001 | HIGH |
| **D009** | Unusual Parent-Child Process Relationship | Windows (Sysmon) | Execution | T1059 | CRITICAL |
| **D010** | Unexpected Scheduled Task Creation | Windows (Sysmon) | Persistence | T1053.005 | MEDIUM |
| **D011** | Suspicious Process Access to LSASS | Windows (Sysmon) | Credential Access | T1003.001 | CRITICAL |
| **D012** | Unexpected Driver Loading | Windows (Sysmon) | Persistence | T1543.003 | HIGH |
| **D013** | Security Event Log Clearing | Windows (Sysmon) | Defense Evasion | T1070.001 | CRITICAL |
| **D014** | Unusual Outbound Network Connection | Network (Suricata) | Command & Control | T1071.001 | MEDIUM |
| **D015** | Known IOC Communication | Network (Suricata) | Command & Control | T1071 | HIGH |
| **D016** | Protected System File Modification | Windows/Linux | Impact | T1565.001 | HIGH |
| **D017** | Repeated Authentication Failures Single Source | Cross-Platform | Credential Access | T1110 | MEDIUM |
| **D018** | Unusual Administrative Service Activity | Windows (Sysmon) | Persistence | T1569.002 | HIGH |

---

## 2. Multi-Stage Correlation Scenarios

### C001 — Linux Account Compromise Sequence
- **Pattern:** `D001` (Brute force failures) $\rightarrow$ `D002` (Successful login) $\rightarrow$ `D004` (Privileged execution)
- **Time Window:** 30 minutes
- **Severity Elevation:** Elevates to `CRITICAL`

### C002 — Windows Execution Chain
- **Pattern:** `D009` (Office spawning cmd/powershell) $\rightarrow$ `D008` (Encoded PowerShell execution) $\rightarrow$ `D014` (Outbound C2 port)
- **Time Window:** 15 minutes
- **Severity Elevation:** Elevates to `CRITICAL`

### C003 — IOC-Associated Multi-Stage Threat
- **Pattern:** `D015` (IOC match) $\rightarrow$ Host activity on same asset
- **Time Window:** 60 minutes
- **Severity Elevation:** Elevates to `HIGH`

### C004 — Account and Persistence Manipulation
- **Pattern:** `D005` (New account creation) $\rightarrow$ `D007` or `D010` (Service/Task persistence)
- **Time Window:** 20 minutes
- **Severity Elevation:** Elevates to `HIGH`
