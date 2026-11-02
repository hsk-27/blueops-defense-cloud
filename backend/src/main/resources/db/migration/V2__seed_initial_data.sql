-- =============================================================================
-- BlueOps Initial Reference Seed Data (Flyway V2__seed_initial_data.sql)
-- =============================================================================

-- 1. Initial Lab Assets
INSERT INTO assets (persistent_id, hostname, ip_address, os_name, os_version, environment, status, criticality, last_telemetry_at)
VALUES
('WIN-ASSET-001', 'LAB-WIN-01', '192.168.56.101', 'Windows', '11 Enterprise 23H2', 'LAB', 'HEALTHY', 'HIGH', CURRENT_TIMESTAMP),
('LNX-ASSET-001', 'LAB-LNX-01', '192.168.56.102', 'Ubuntu', '22.04 LTS Jammy', 'LAB', 'HEALTHY', 'HIGH', CURRENT_TIMESTAMP),
('NET-ASSET-001', 'LAB-FW-01', '192.168.56.1', 'FreeBSD', 'Suricata Sensor 7.0', 'LAB', 'HEALTHY', 'CRITICAL', CURRENT_TIMESTAMP);

-- 2. Initial 18 Detection Rules
INSERT INTO detection_rules (rule_code, name, description, log_source, severity, mitre_tactic, mitre_technique_id, mitre_technique_name, status, query_dsl, sigma_yaml, false_positives, version)
VALUES
('D001', 'Repeated SSH Authentication Failures', 'Detects repeated failed SSH authentication attempts from a single source within a short time window.', 'linux_auditd', 'MEDIUM', 'Credential Access', 'T1110.001', 'Password Guessing', 'ACTIVE', 'event.action:ssh_login AND event.outcome:failure', 'title: Repeated SSH Authentication Failures\nid: D001\nlogsource:\n  product: linux\n  service: sshd\ndetection:\n  selection:\n    event.action: ssh_login\n    event.outcome: failure\n  timeframe: 5m\n  condition: selection | count(event.id) by source.ip > 5', 'Administrative password mistypes; authorized penetration tests.', 1),

('D002', 'Successful SSH Login After Repeated Failures', 'Detects a successful authentication event preceded by multiple failed login attempts on the same account.', 'linux_auditd', 'HIGH', 'Credential Access', 'T1110', 'Brute Force', 'ACTIVE', 'event.action:ssh_login AND event.outcome:success', 'title: Successful SSH Login After Failures\nid: D002\nlogsource:\n  product: linux\n  service: sshd', 'Legitimate user recovering from forgotten password.', 1),

('D003', 'Password Spraying', 'Detects authentication failures targeting multiple distinct user accounts from a single external IP.', 'linux_auditd', 'HIGH', 'Credential Access', 'T1110.003', 'Password Spraying', 'ACTIVE', 'event.action:authentication AND event.outcome:failure', 'title: Password Spraying\nid: D003', 'Misconfigured enterprise sync services or automated inventory sweeps.', 1),

('D004', 'Unexpected Privileged Command Execution', 'Detects execution of high-risk binaries or interactive shells via sudo by unauthorized service accounts.', 'linux_auditd', 'HIGH', 'Privilege Escalation', 'T1548.003', 'Sudo and Sudo Caching', 'ACTIVE', 'process.executable:/usr/bin/sudo AND (process.command_line:*bash* OR process.command_line:*sh*)', 'title: Unexpected Privileged Command Execution\nid: D004', 'Scheduled system administration or maintenance scripts running as root.', 1),

('D005', 'Privileged Account Creation', 'Detects the creation of new user accounts or additions to administrative groups (wheel, sudo, root).', 'linux_auditd', 'HIGH', 'Persistence', 'T1136.001', 'Local Account', 'ACTIVE', 'process.executable:*useradd* OR process.executable:*usermod* OR file.path:/etc/passwd', 'title: Privileged Account Creation\nid: D005', 'Authorized onboarding of system personnel via automated scripts.', 1),

('D006', 'Audit Configuration Tampering', 'Detects modification, stopping, or unloading of Linux audit subsystem rules and daemons.', 'linux_auditd', 'CRITICAL', 'Defense Evasion', 'T1562.001', 'Disable or Modify Tools', 'ACTIVE', 'file.path:/etc/audit/* OR process.executable:*auditctl*', 'title: Audit Configuration Tampering\nid: D006', 'Authorized kernel updates or audit policy reconfigurations by sysadmins.', 1),

('D007', 'Suspicious System Service Creation', 'Detects creation or modification of systemd unit files in /etc/systemd/system.', 'linux_auditd', 'MEDIUM', 'Persistence', 'T1543.002', 'Systemd Service', 'ACTIVE', 'file.path:/etc/systemd/system/* AND event.action:file_created', 'title: Suspicious System Service Creation\nid: D007', 'Legitimate package installations or server provisioning.', 1),

('D008', 'Suspicious PowerShell Execution', 'Detects PowerShell executed with encoded commands, execution policy bypass, or download cradles.', 'windows_sysmon', 'HIGH', 'Execution', 'T1059.001', 'PowerShell', 'ACTIVE', 'process.name:powershell.exe AND (process.command_line:*EncodedCommand* OR process.command_line:*-enc* OR process.command_line:*DownloadString*)', 'title: Suspicious PowerShell Execution\nid: D008', 'Legitimate administrative PowerShell automation scripts with base64 encoded parameters.', 1),

('D009', 'Unusual Parent-Child Process Relationship', 'Detects office applications, browsers, or web servers spawning cmd.exe, powershell.exe, or wscript.exe.', 'windows_sysmon', 'CRITICAL', 'Execution', 'T1059', 'Command and Scripting Interpreter', 'ACTIVE', 'process.parent.name:(winword.exe OR excel.exe OR powerpnt.exe) AND process.name:(cmd.exe OR powershell.exe)', 'title: Unusual Parent-Child Process\nid: D009', 'Complex legitimate Word/Excel add-ins executing localized helper tools.', 1),

('D010', 'Unexpected Scheduled Task Creation', 'Detects creation of scheduled tasks using schtasks.exe pointing to scripts or temporary folders.', 'windows_sysmon', 'MEDIUM', 'Persistence', 'T1053.005', 'Scheduled Task', 'ACTIVE', 'process.name:schtasks.exe AND process.command_line:*/create*', 'title: Unexpected Scheduled Task Creation\nid: D010', 'Software updaters (Google Update, Edge Update) creating recurring tasks.', 1),

('D011', 'Suspicious Process Access', 'Detects attempts to access LSASS memory with high-privilege access rights indicating credential dumping.', 'windows_sysmon', 'CRITICAL', 'Credential Access', 'T1003.001', 'LSASS Memory', 'ACTIVE', 'event.action:process_access AND process.parent.name:lsass.exe', 'title: Suspicious Process Access\nid: D011', 'Antivirus scanners and endpoint security monitoring agents querying process tokens.', 1),

('D012', 'Unexpected Driver Loading', 'Detects loading of unsigned or unusual kernel drivers potentially indicating rootkits or BYOVD attacks.', 'windows_sysmon', 'HIGH', 'Persistence', 'T1543.003', 'Kernel Drivers', 'ACTIVE', 'event.action:driver_loaded', 'title: Unexpected Driver Loading\nid: D012', 'Hardware vendor diagnostics or virtualization hypervisor extensions.', 1),

('D013', 'Security Event Log Clearing', 'Detects attempts to clear Windows security event logs via wevtutil or PowerShell Clear-EventLog.', 'windows_sysmon', 'CRITICAL', 'Defense Evasion', 'T1070.001', 'Clear Windows Event Logs', 'ACTIVE', 'process.command_line:(*wevtutil*cl* OR *Clear-EventLog*)', 'title: Security Event Log Clearing\nid: D013', 'Routine lab maintenance or disk cleanup batch jobs.', 1),

('D014', 'Unusual Outbound Network Connection', 'Detects outbound connections to anomalous external ports frequently associated with C2 (4444, 1337, 8888).', 'suricata', 'MEDIUM', 'Command and Control', 'T1071.001', 'Web Protocols', 'ACTIVE', 'destination.port:(4444 OR 1337 OR 8888) AND network.direction:outbound', 'title: Unusual Outbound Network Connection\nid: D014', 'Development web services running on non-standard ports.', 1),

('D015', 'Known IOC Communication', 'Detects endpoint or network communication matching high-confidence threat intelligence indicators.', 'suricata', 'HIGH', 'Command and Control', 'T1071', 'Application Layer Protocol', 'ACTIVE', 'destination.ip:KNOWN_IOC OR dns.query:KNOWN_IOC', 'title: Known IOC Communication\nid: D015', 'Security researchers pinging benign sinkholes.', 1),

('D016', 'Protected-File Modification', 'Detects modification of critical security configuration files or system hosts files.', 'windows_sysmon', 'HIGH', 'Impact', 'T1565.001', 'Stored Data Manipulation', 'ACTIVE', 'file.path:(*System32\\drivers\\etc\\hosts* OR */etc/hosts*)', 'title: Protected-File Modification\nid: D016', 'Network administrators editing hosts file for local internal resolution.', 1),

('D017', 'Repeated Authentication Failures From a Single Source', 'Cross-platform aggregation of authentication failures originating from an unclassified internal IP.', 'suricata', 'MEDIUM', 'Credential Access', 'T1110', 'Brute Force', 'ACTIVE', 'event.category:authentication AND event.outcome:failure', 'title: Repeated Authentication Failures\nid: D017', 'Users with cached expired credentials in email clients or file shares.', 1),

('D018', 'Unusual Administrative Service Activity', 'Detects creation or dynamic modification of Windows services via sc.exe create or New-Service.', 'windows_sysmon', 'HIGH', 'Persistence', 'T1569.002', 'Service Execution', 'ACTIVE', 'process.name:sc.exe AND process.command_line:*create*', 'title: Unusual Administrative Service Activity\nid: D018', 'Legitimate installer executables installing local background services.', 1);

-- 3. Response Playbooks
INSERT INTO response_playbooks (playbook_code, name, description, action_type, requires_approval, target_type, rollback_supported)
VALUES
('P001', 'Block Suspicious Lab IP', 'Inserts a drop rule on the lab perimeter firewall for the identified malicious source IP.', 'BLOCK_IP', TRUE, 'IP', TRUE),
('P002', 'Disable Compromised Test Account', 'Locks and disables authentication credentials for an identified compromised lab account.', 'DISABLE_USER', TRUE, 'USERNAME', TRUE),
('P003', 'Isolate Suspicious Lab Endpoint', 'Applies dynamic network isolation rules to sever non-management connectivity to the asset.', 'ISOLATE_HOST', TRUE, 'ASSET', TRUE),
('P004', 'Restore Lab IP Communication', 'Removes the drop rule from the lab perimeter firewall, restoring network reachability.', 'RESTORE_IP', FALSE, 'IP', FALSE),
('P005', 'Re-enable Lab Test Account', 'Unlocks and restores authentication access for the lab user account.', 'ENABLE_USER', FALSE, 'USERNAME', FALSE),
('P006', 'Reconnect Isolated Lab Endpoint', 'Restores full network connectivity to the previously quarantined lab asset.', 'RECONNECT_HOST', FALSE, 'ASSET', FALSE),
('P007', 'Collect Endpoint Evidence Archive', 'Acquires forensic artifacts, triage memory dumps, and relevant audit logs.', 'COLLECT_EVIDENCE', FALSE, 'ASSET', FALSE);

-- 4. Initial Threat Intelligence Indicators (Sample IOCs)
INSERT INTO ioc_indicators (indicator_value, indicator_type, source, confidence, severity, description, status, tags)
VALUES
('198.51.100.24', 'IP', 'CISA_ALERT', 95, 'CRITICAL', 'C2 IP associated with adversary simulation campaign', 'ACTIVE', 'c2,apt,malware'),
('evil-corp.blueops.lab', 'DOMAIN', 'INTERNAL_THREAT_RESEARCH', 90, 'HIGH', 'Simulated phishing and payload delivery domain', 'ACTIVE', 'phishing,payload'),
('http://evil-corp.blueops.lab/payload.exe', 'URL', 'INTERNAL_THREAT_RESEARCH', 90, 'HIGH', 'Adversary drop URL for simulation payload', 'ACTIVE', 'payload,stager'),
('e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855', 'SHA256', 'OTX_ALIENVAULT', 85, 'HIGH', 'Known test trojan payload hash', 'ACTIVE', 'trojan,mimikatz');
