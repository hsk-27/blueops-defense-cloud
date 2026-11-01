# BlueOps — Operations & Troubleshooting Guide

## 1. Common Operational Scenarios

### 1.1 OpenSearch Container Out-of-Memory (OOM)
- **Symptom:** OpenSearch container exits with code 137.
- **Cause:** Host system has less than 3 GB available free memory or memory limit in `docker-compose.yml` was exceeded.
- **Resolution:** Verify `-Xms1g -Xmx1g` in `docker-compose.yml`. Ensure heavy host applications (e.g. video rendering, extra VMs) are paused during lab sessions.

### 1.2 OpenSearch Cluster Temporarily Unreachable
- **Symptom:** Spring Boot logs `OpenSearch cluster is currently unreachable`.
- **Resolution:** This is handled gracefully by design. The `OpenSearchFindingAdapter` automatically caches local detection findings and continues operating without failing backend HTTP endpoints. Once the cluster finishes booting, synchronizations resume seamlessly.

### 1.3 Windows Fluent Bit Does Not Forward Sysmon Events
- **Symptom:** No events appearing in `blueops-events-*`.
- **Checks:**
  1. Confirm Sysmon service is running: `Get-Service Sysmon64`.
  2. Confirm Fluent Bit service is active: `Get-Service fluent-bit`.
  3. Verify firewall connectivity between Windows VM and central platform: `Test-NetConnection -ComputerName <IP> -Port 5140`.

### 1.4 Response Agent Signature Mismatch
- **Symptom:** Agent logs `HMAC verification failed for action ID ...` (HTTP 401).
- **Checks:**
  1. Ensure both Spring Boot and Response Agent share the same `RESPONSE_AGENT_SECRET` value.
  2. Confirm host and container clocks are synchronized within 60 seconds (anti-replay threshold).
