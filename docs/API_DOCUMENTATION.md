# BlueOps — REST API Documentation (v1)

Base URI: `/api/v1`  
Authentication: Bearer JWT (`Authorization: Bearer <token>`)

---

## 1. Authentication
- `POST /auth/login`: Authenticate with username and password. Returns access token, refresh token, role, and profile.
- `POST /auth/refresh`: Refresh access token with valid refresh token.
- `POST /auth/logout`: Invalidate current token session.
- `GET /auth/me`: Get current authenticated user profile.

---

## 2. Asset Management
- `GET /assets`: List all monitored assets with health status.
- `GET /assets/{id}`: Get specific asset by ID.
- `POST /assets`: Register a new monitored endpoint (Role: ADMIN, ANALYST).
- `PUT /assets/{id}`: Update asset metadata or operational status.
- `DELETE /assets/{id}`: Deregister asset (Role: ADMIN).
- `GET /assets/{id}/history`: Retrieve asset status change audit history.

---

## 3. Detection Rules & Findings
- `GET /detections`: List all 18 Sigma-compatible detection rules.
- `GET /detections/{id}`: Get rule details, MITRE ATT&CK mapping, and query DSL.
- `PUT /detections/{id}/status?status={ACTIVE|DISABLED|TESTING}`: Enable/disable rule (Role: ADMIN).
- `GET /detections/findings`: List all security analytics findings from OpenSearch.
- `GET /detections/summary`: Summary of rule distribution across platforms.

---

## 4. Incident Center & Investigation
- `GET /incidents`: Query incidents with optional `status`, `severity`, and pagination.
- `POST /incidents`: Create incident from detected findings.
- `GET /incidents/{id}`: Get incident details.
- `GET /incidents/{id}/timeline`: Retrieve chronological investigation timeline.
- `GET /incidents/{id}/findings`: Retrieve attached OpenSearch findings.
- `POST /incidents/{id}/notes`: Add analyst investigation note.
- `PUT /incidents/{id}/assign`: Assign incident to analyst.
- `PUT /incidents/{id}/status`: Transition incident status (validated by state machine).
- `POST /incidents/{id}/reopen`: Reopen resolved or false-positive incident.

---

## 5. Threat Intelligence
- `GET /threat-intel/iocs`: List all IOC indicators.
- `POST /threat-intel/iocs`: Register new IOC indicator.
- `GET /threat-intel/iocs/{id}`: Get IOC indicator details.
- `PUT /threat-intel/iocs/{id}`: Update confidence, status, or description.
- `DELETE /threat-intel/iocs/{id}`: Delete indicator (Role: ADMIN).
- `POST /threat-intel/import`: Bulk import indicators via CSV string.
- `GET /threat-intel/matches`: Retrieve telemetry matched against active IOCs.
- `GET /threat-intel/sources`: List threat intel provider sources.

---

## 6. Response Orchestration
- `GET /response/playbooks`: List available response playbooks.
- `GET /response/playbooks/{code}`: Get playbook configuration.
- `POST /response/actions`: Request execution of a playbook.
- `GET /response/actions`: List recent action requests.
- `POST /response/actions/{id}/approve`: Approve action (Role: ADMIN).
- `POST /response/actions/{id}/reject`: Reject action (Role: ADMIN).
- `POST /response/actions/{id}/execute`: Directly execute approved action.
- `POST /response/actions/{id}/rollback`: Initiate automated rollback.
- `GET /response/executions`: List response execution logs and duration telemetry.

---

## 7. Audit & Reporting
- `GET /audit/logs`: Paginated compliance audit trail.
- `GET /reports/overview`: SOC operational metrics, MTTD, MTTR, and health status.
- `GET /reports/attack-coverage`: MITRE ATT&CK detection coverage matrix.
