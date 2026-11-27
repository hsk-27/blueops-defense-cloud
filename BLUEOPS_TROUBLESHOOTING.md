# BlueOps Operational Troubleshooting & Diagnostics Guide (M7)

**Document ID:** BLUEOPS-DOC-M7-004  
**Milestone:** M7 Operational Hardening & Reliability  
**Classification:** Engineering & Operations Support Manual  

---

## 1. Troubleshooting Quick Reference Matrix

| Symptom | Probable Cause | Diagnostic Command / Log | Remediation Action |
| :--- | :--- | :--- | :--- |
| **Backend fails on boot** | Secret validation failed (`SecurityStartupValidator`) | `IllegalStateException` citing insecure/default JWT or HMAC secret | Supply high-entropy 256-bit keys via `JWT_SECRET` and `RESPONSE_AGENT_SECRET`. |
| **Fluent Bit gets 401/403 on `/api/v1/telemetry/ingest`** | Missing or mismatched `BLUEOPS_INGEST_API_KEY` | Collector auth fails closed in `JwtAuthenticationFilter` | Set identical `BLUEOPS_INGEST_API_KEY` in `backend` and `fluent-bit` containers (`X-BlueOps-Ingest-Key`). |
| **Events rejected / DLQ growing** | Malformed payloads or replay ceiling | `GET /api/v1/telemetry/dlq` | Correct source log format; invoke `POST /api/v1/telemetry/dlq/replay`. |
| **OpenSearch connection refused** | Container not running / disabled | `OpenSearch cluster is currently unreachable ... Serving from local finding store` | Platform operates automatically with in-memory finding store (volatile on restart). |
| **Response Agent returns 401** | HMAC signature mismatch or clock skew | `Signature expired. Server time: X, Token timestamp: Y` | Verify NTP synchronization between backend and agent; verify matching `RESPONSE_AGENT_SECRET`. |
| **Response Agent returns 409** | Replay detected / duplicate ActionId | `Replay detected: ActionId already processed` | Ensure unique UUIDv4 is generated per response action request. |
| **Response Action rejected (400)** | Shell injection, CLI option leading hyphen, or whitespace | `Target parameter cannot begin with hyphen (CLI option injection rejected)` | Sanitize target input. Ensure strict format compliance (e.g. single IP or hostname without arguments). |
| **Flyway Checksum Mismatch** | Migration SQL file edited post-application | `FlywayValidateException: Validate failed: Migrations have failed validation` | Run Flyway repair: `java -jar app.jar --spring.flyway.repair=true`. Never edit applied migrations. |
| **Pytest import error in CI** | `ImportError: cannot import name 'evict_expired_nonces'` | `response-agent/tests/test_agent.py` | Import alias `evict_expired_nonces` exposed in `src/agent.py` (Fixed in M7). |

---

## 2. Ingestion Pipeline & Dead-Letter Queue (DLQ) Troubleshooting

### 2.1 Diagnosing High DLQ Count
Query `/api/v1/telemetry/dlq`:
```bash
curl -s -H "Authorization: Bearer $TOKEN" "http://localhost:8080/api/v1/telemetry/dlq?limit=10" | jq .
```
Common DLQ errors:
1. `INVALID_EVENT_TIMESTAMP`: Telemetry source emitting local non-ISO timestamps.
   - *Fix:* Ensure log forwarders (Sysmon / Filebeat) output ISO-8601 UTC (`yyyy-MM-dd'T'HH:mm:ss.SSSX`).
2. `MISSING_PROVIDER_IDENTIFIER`: Telemetry payload lacks provider name (`provider` or `source`).
   - *Fix:* Configure forwarder to include `provider: Sysmon` or `provider: LinuxAuditd`.

### 2.2 Replaying Quarantined Events
```bash
curl -X POST -H "Authorization: Bearer $ADMIN_TOKEN" "http://localhost:8080/api/v1/telemetry/dlq/replay" | jq .
```
If payloads fail repeatedly, the **Poison-Pill Guard** diverts them after 3 re-attempts (`quarantinedPoisonPills > 0`). These will not block future replays.

---

## 3. Storage & OpenSearch Cluster Disconnect

### 3.1 Fallback Architecture Behavior
BlueOps is engineered for zero-downtime search resilience:
- When OpenSearch is available: Findings are indexed into `/blueops-findings-lab` and queried in real-time.
- When OpenSearch is offline: `OpenSearchFindingAdapter` automatically logs a warning and routes all read and write queries to its local in-memory store and PostgreSQL database finding audit trail.
- **Analyst Impact:** Incident investigation and detection generation continue uninterrupted.

### 3.2 Restoring OpenSearch Connection
1. Check OpenSearch container health:
   ```bash
   docker ps -f name=blueops-opensearch
   docker logs --tail 50 blueops-opensearch
   ```
2. If OpenSearch suffered an Out-Of-Memory (OOM) event, verify `vm.max_map_count`:
   ```bash
   sysctl -w vm.max_map_count=262144
   ```
3. Restart OpenSearch:
   ```bash
   docker compose restart opensearch
   ```
4. Query `/api/v1/system/health` to confirm `storageFallback` status.

---

## 4. Response Agent & SOAR Diagnostic Procedures

### 4.1 HMAC-SHA256 Authentication Errors
If `RestrictedAgentResponseAdapter` reports:
`Failed to execute action on remote response agent: 401 Unauthorized`

1. **Verify Shared Secret:**
   Check backend configuration:
   ```bash
   echo $RESPONSE_AGENT_SECRET
   ```
   Check response-agent configuration:
   ```bash
   docker exec blueops-response-agent env | grep RESPONSE_AGENT_SECRET
   ```
2. **Verify System Clocks (NTP):**
   The agent enforces an anti-replay window of **60 seconds**.
   If the backend and agent system clocks differ by more than 60 seconds, requests are rejected with:
   `Signature expired. Server time: ..., Token timestamp: ...`
   *Solution:* Sync clocks using `chronyd` or `ntpdate pool.ntp.org`.

### 4.2 Parameter Validation Rejections
If the response agent returns `HTTP 400 REJECTED_INVALID_PARAMETER`:
- **CLI Option Flag Injection:** Target parameter begins with a hyphen (e.g. `-f`, `--help`, `-exec`).
- **Whitespace Argument Injection:** Target parameter contains whitespace characters (e.g. `198.51.100.24 10.0.0.1`).
- **Forbidden Shell Metacharacters:** Target contains `;`, `&`, `|`, `` ` ``, `$`, `>`, `<`, `\r`, `\n`.
*Solution:* BlueOps security policy strictly forbids compound or multi-argument execution. Enter the bare target identifier only.

---

## 5. JVM Memory & Garbage Collection Tuning

If the backend experiences latency spikes under heavy ingestion:
1. Inspect JVM metrics via `/api/v1/system/diagnostics`:
   ```json
   "memory": {
     "maxMemoryMb": 4096,
     "usedMemoryMb": 3412,
     "heapUtilizationPct": 83.3
   }
   ```
2. Recommended JVM flags in production:
   ```bash
   -XX:+UseG1GC
   -XX:MaxRAMPercentage=75.0
   -XX:InitiatingHeapOccupancyPercent=45
   -XX:G1ReservePercent=15
   ```
3. Check thread states:
   ```bash
   jcmd $(pgrep -f blueops-backend) Thread.print
   ```

---

## 6. Frontend Build & Vitest Diagnostics

### 6.1 Node.js Build Memory Issues
In constrained CI runners, Vite bundle creation may fail due to memory limits.
*Solution:* Set `NODE_OPTIONS="--max-old-space-size=4096"`.

### 6.2 TypeScript Compilation Check
Before pushing any frontend modifications, always run:
```bash
npx tsc --noEmit
```
Ensure zero type errors.
