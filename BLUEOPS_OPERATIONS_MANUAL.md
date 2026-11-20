# BlueOps Security Operations & Incident Handling Manual (M7)

**Document ID:** BLUEOPS-DOC-M7-002  
**Milestone:** M7 Operational Hardening & Reliability  
**Classification:** Internal Security Operations Procedures (SOP)  
**Target Audience:** Tier-1/2 SOC Analysts, Incident Responders, Detection Engineers  

---

## 1. Scope & Daily SOC Operational Baseline

This manual specifies the standard operating procedures for operating the BlueOps Defensive Cybersecurity Platform in enterprise and laboratory security environments.

### 1.1 Shift Handover & Daily Readiness Checklist
At the beginning of each SOC shift, the duty analyst must verify platform readiness:
1. **Health Verification:** Probe `/api/v1/system/health` and Actuator `/actuator/health`.
   - Confirm `database: CONNECTED`
   - Confirm `rulesEngine: OPERATIONAL`
   - Confirm `platformStatus: OPERATIONAL`
2. **Buffer & DLQ Check:** Query `/api/v1/system/diagnostics` or `/api/v1/telemetry/stats`.
   - Verify `bufferedCount` reflects healthy streaming ingestion.
   - Verify `dlqCount` is under threshold (< 50 items). If elevated, follow Section 3 (DLQ Management).
3. **SOAR Mode Check:** Confirm `defaultMode: SIMULATION` in lab environments, or verified policy bounds in staging.

---

## 2. Ingestion Pipeline & Telemetry Monitoring

BlueOps continuously normalizes multi-source telemetry into canonical events:
- **Sources:** Windows Sysmon (EventIDs 1, 3, 5, 11, 12, 13, 22), Linux Auditd / Auth logs, Zeek / Suricata network telemetry, Threat Intel feeds.
- **Normalization Engine:** `EventNormalizationService` validates timestamp syntax, sanitizes identifiers, and extracts entities into the M5 context graph.

### 2.1 Ingestion Throughput Monitoring
- Normal baseline throughput: 500 – 5,000 events/sec per node.
- Memory utilization: G1GC managed, target heap usage < 75%.
- Event drops: Any buffer saturation triggers warning logs and automatically preserves high-severity findings while backpressuring ingestion.

---

## 3. Dead-Letter Queue (DLQ) & Poison-Pill Handling

When incoming events violate schema constraints, contain unparseable timestamps, or exhibit structural corruption, they are diverted to the Dead-Letter Queue (DLQ) rather than halting the ingestion stream.

### 3.1 DLQ Inspection
Analysts can inspect quarantined events via the UI (`LiveTelemetryPage.tsx`) or API:
```http
GET /api/v1/telemetry/dlq?limit=50
Authorization: Bearer <TOKEN>
```

### 3.2 Automated Replay Procedure
Once upstream format issues are corrected:
```http
POST /api/v1/telemetry/dlq/replay
Authorization: Bearer <ADMIN_TOKEN>
```
Response:
```json
{
  "status": "SUCCESS",
  "replayedCount": 45,
  "recoveredCount": 43,
  "quarantinedPoisonPills": 2,
  "findingsGenerated": 3
}
```

### 3.3 Poison-Pill Quarantine Protection
- **Rule:** If an event payload fails normalization 3 consecutive times during replay attempts (`dlq_replay_count >= 3`), the poison-pill guard intercepts it.
- **Action:** The event is permanently quarantined into an isolated secondary audit log to prevent infinite loops, buffer exhaustion, or CPU starvation.

---

## 4. Detection Engineering & Rule Lifecycle

BlueOps supports dynamic Sigma YAML rules and cross-event correlation rules.

### 4.1 Adding a New Sigma Rule
1. Author rule in `detection-rules/sigma/<category>/<technique>.yml`.
2. Ensure mandatory fields are populated:
   - `id`: Unique UUIDv4
   - `title`: Descriptive name
   - `status`: `stable` | `experimental`
   - `logsource`: Product and service definition
   - `detection`: Selections, filters, and boolean condition AST
   - `level`: `low` | `medium` | `high` | `critical`
   - `tags`: MITRE ATT&CK tactic and technique IDs (`attack.t1059.001`)

### 4.2 Atomic Zero-Downtime Rule Reload
To load new or modified Sigma rules without restarting the backend:
```http
POST /api/v1/detections/reload
Authorization: Bearer <ADMIN_TOKEN>
```
- **Mechanism:** `SigmaRuleRegistry` parses rules into staging maps and executes an atomic reference swap (`rulesByCodeRef.set()`). Concurrent evaluation queries never block and never encounter empty states.

---

## 5. Incident Triage, Investigation & Context Pivoting

When a detection rule evaluates to `true`, a finding is generated and persisted.

### 5.1 Finding Triage Workflow
1. Navigate to **Incident Center** or **Findings**.
2. Review finding severity, MITRE tactics, and primary entities (Source IP, Hostname, Username).
3. Check M5 Context Graph:
   - View associated entity observations (`/api/v1/entities/{id}/observations`).
   - Inspect entity relationships (`/api/v1/entities/{id}/relationships`).
   - Review correlated findings (`/api/v1/detections/findings/{id}/related`).

### 5.2 Incident Escalation & Case Management
1. Promote finding or correlation group to an Incident (`POST /api/v1/incidents`).
2. Assign priority (`P1_CRITICAL`, `P2_HIGH`, `P3_MEDIUM`, `P4_LOW`).
3. Assign lead investigator and append forensic timeline notes.

---

## 6. Controlled SOAR Response Governance

BlueOps incorporates strict human-in-the-loop and Separation of Duties policy controls to prevent accidental host disruption or unauthorized execution.

### 6.1 SOAR Safety Guarantees
- **Deny-by-Default:** Any action, target, or parameter not explicitly allowlisted is immediately rejected.
- **Zero Host Mutation Guard:** In all testing and development environments, `ALLOW_LIVE_HOST_DISRUPTION = false`. Drivers operate in simulated lab mode.
- **Two-Man Rule (Separation of Duties):** The user who creates a response proposal (`proposer`) cannot approve that same proposal. A distinct administrative user (`approver`) must review and approve.
- **Pre-Flight Policy Preview:** The engine evaluates target safety, CIDR boundaries, and risk tier before any proposal is submitted.

### 6.2 Response Action Execution Lifecycle
```
Finding / Incident
       │
       ▼
1. Pre-Flight Preview (POST /api/v1/response/soar/policy-preview)
       │
       ▼
2. Create Proposal (POST /api/v1/response/soar/proposals) [Status: PENDING_APPROVAL]
       │
       ▼
3. Independent Approval (POST /api/v1/response/soar/proposals/{id}/approve) [Status: APPROVED]
       │
       ▼
4. Execution (POST /api/v1/response/soar/proposals/{id}/execute)
       │  (HMAC-SHA256 Token Generation & Nonce Registration)
       ▼
5. Independent Verification (ResponseVerificationEngine state probe & SHA-256 evidence record)
```

---

## 7. Emergency Procedures & Incident Escalation Contacts

In the event of an active critical threat or suspected platform compromise:
1. Isolate the target asset via BlueOps SOAR Proposal `ACT-003` (`ISOLATE_HOST`).
2. Preserve in-memory telemetry buffer and dump active findings:
   ```bash
   curl -X GET "http://localhost:8080/api/v1/telemetry/events?limit=500" -H "Authorization: Bearer <TOKEN>" > forensic_dump.json
   ```
3. Contact the on-call Incident Response Commander immediately.
