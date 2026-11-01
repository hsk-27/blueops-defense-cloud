# BlueOps — Linux Endpoint Telemetry Setup Guide

## 1. Prerequisites
- Ubuntu 22.04/24.04 LTS or Debian/RHEL Lab Virtual Machine
- Root or sudo privileges
- Network access to BlueOps Fluent Bit (TCP 5140)

## 2. Configure Linux Audit Subsystem (auditd)
1. Install auditd:
   ```bash
   sudo apt-get update && sudo apt-get install -y auditd audispd-plugins
   ```
2. Copy the BlueOps rules:
   ```bash
   sudo cp infrastructure/linux/audit-rules/audit.rules /etc/audit/rules.d/blueops.rules
   sudo augenrules --load
   sudo systemctl restart auditd
   ```
3. Verify rules are loaded:
   ```bash
   sudo auditctl -l
   ```

## 3. Forward Telemetry with Fluent Bit (Linux)
1. Install Fluent Bit:
   ```bash
   curl https://raw.githubusercontent.com/fluent/fluent-bit/master/install.sh | sh
   ```
2. Configure `/etc/fluent-bit/fluent-bit.conf` to tail `/var/log/audit/audit.log` and `/var/log/auth.log` (or systemd journal) and forward to BlueOps:
   ```ini
   [INPUT]
       Name        tail
       Path        /var/log/audit/audit.log
       Tag         linux.audit
       Parser      linux_auditd

   [INPUT]
       Name        systemd
       Tag         linux.journal
       Systemd_Filter _COMM=sshd
       Systemd_Filter _COMM=sudo

   [OUTPUT]
       Name        tcp
       Match       linux.*
       Host        <BLUEOPS_SERVER_IP>
       Port        5140
       Format      json
   ```
3. Enable and start Fluent Bit:
   ```bash
   sudo systemctl enable --now fluent-bit
   ```
