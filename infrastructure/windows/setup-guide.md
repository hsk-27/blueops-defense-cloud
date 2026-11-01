# BlueOps — Windows Endpoint Telemetry Setup Guide

## 1. Prerequisites
- Windows 10/11 or Windows Server 2019/2022 Lab Virtual Machine
- Administrator Privileges
- Network connectivity to BlueOps Fluent Bit (TCP 5140)

## 2. Install Sysmon
1. Download Microsoft Sysinternals Sysmon:
   `https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon`
2. Open PowerShell as Administrator.
3. Install Sysmon using the BlueOps schema:
   ```powershell
   .\Sysmon64.exe -accepteula -i .\sysmon-config.xml
   ```
4. Verify service status:
   ```powershell
   Get-Service Sysmon64
   ```

## 3. Forward Telemetry with Fluent Bit (Windows)
1. Install Fluent Bit for Windows:
   `winget install FluentBit`
2. Configure `C:\Program Files\fluent-bit\conf\fluent-bit.conf` to read the Windows Event Log channel `Microsoft-Windows-Sysmon/Operational` and forward in JSON format to the central BlueOps Fluent Bit listener:
   ```ini
   [INPUT]
       Name         winevtlog
       Channels     Microsoft-Windows-Sysmon/Operational,Security
       Interval_Sec 1
       DB           /winevt.db

   [OUTPUT]
       Name         tcp
       Match        *
       Host         <BLUEOPS_SERVER_IP>
       Port         5140
       Format       json
   ```
3. Restart Fluent Bit service:
   ```powershell
   Restart-Service fluent-bit
   ```
