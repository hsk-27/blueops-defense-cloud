# BlueOps — Platform Security Model & Defense-in-Depth

## 1. Authentication & RBAC
- **Token Security:** HMAC-SHA256 JWT tokens with 1-hour expiration and 24-hour rotating refresh tokens.
- **Password Storage:** Salted BCrypt password encoding with cost factor 10.
- **Role Hierarchy:**
  - `ROLE_ADMIN`: User management, detection rule enablement, threat intel deletion, playbook approval, rollback execution.
  - `ROLE_ANALYST`: Incident triage, note creation, status transitions, playbook execution requests.
  - `ROLE_VIEWER`: Read-only access to dashboards, reports, and audit logs.

---

## 2. Response Action Security Boundaries
- **No Remote Shell:** Arbitrary shell execution (`cmd.exe`, `bash`) is architecturally forbidden.
- **Allowlisted Actions:** Agents only accept predefined structured actions (`BLOCK_IP`, `DISABLE_USER`, `ISOLATE_HOST`, `RESTORE_IP`, `ENABLE_USER`).
- **HMAC Authentication:** Outgoing action requests are cryptographically signed using HMAC-SHA256:
  $$\text{Signature} = \text{HMAC-SHA256}(K, \text{Timestamp} : \text{Payload})$$
- **Replay Protection:** Unique `ActionId` nonces are tracked; requests older than 60 seconds or with duplicate nonces are rejected with HTTP 401/409.
- **Two-Person Integrity:** Consequential playbooks require explicit `ROLE_ADMIN` approval before dispatch.

---

## 3. Network & Data Isolation
- **Secret Isolation:** Passwords and keys are externalized through environment variables and `.env.example`. Real secrets are ignored in `.gitignore`.
- **Database Boundary:** Raw telemetry remains in OpenSearch; only parsed findings and incident metadata reside in PostgreSQL.
- **CORS Policy:** Strict origin allowlist (`http://localhost:3000`, `http://localhost:5173`).
