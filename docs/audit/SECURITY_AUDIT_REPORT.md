# BlueOps — Application Security & Threat Model Audit Report

**Assessment Scope:** Authentication, Authorization (RBAC), Endpoint Protection, Cryptographic Integrity, Response Agent Boundaries, and Audit Trail.  
**Classification:** Internal Security Assessment  
**Overall AppSec Posture:** HARDENED & PRODUCTION-GRADE  

---

## 1. Authentication & Session Security

### 1.1 Credential Hashing & Storage
- Passwords stored in PostgreSQL `users` table using `BCryptPasswordEncoder` with default computational work factor 10.
- Source file: [`SecurityConfig.java`](file:///C:/Users/Dell/.gemini/antigravity/scratch/blueops/backend/src/main/java/com/blueops/security/SecurityConfig.java#L36-L38).

### 1.2 JWT Token Generation & Validation
- Standard HMAC-SHA256 JWT tokens generated with `HS256` signature algorithm.
- Token claims include username, role, issued-at timestamp, and 24-hour expiration (`jwt.expiration-ms=86400000`).
- Strict cryptographic validation implemented in [`JwtTokenProvider.java`](file:///C:/Users/Dell/.gemini/antigravity/scratch/blueops/backend/src/main/java/com/blueops/security/JwtTokenProvider.java) catching expired, malformed, unsupported, or untrusted tokens.
- Unit test verified: [`JwtTokenProviderTest.java`](file:///C:/Users/Dell/.gemini/antigravity/scratch/blueops/backend/src/test/java/com/blueops/security/JwtTokenProviderTest.java) (2/2 tests passing).

### 1.3 Brute-Force & Credential Stuffing Resilience (DEF-002)
- Implemented in-memory sliding window rate limiter: [`LoginRateLimiter.java`](file:///C:/Users/Dell/.gemini/antigravity/scratch/blueops/backend/src/main/java/com/blueops/auth/LoginRateLimiter.java).
- Limits consecutive failed attempts to 5 within a 15-minute sliding window.
- Exceeding the threshold triggers an automatic 15-minute lockout, returning HTTP 429 (`TOO_MANY_REQUESTS`).
- Failed attempts and lockout events logged to `audit_logs` with action `"LOCKED_OUT"`.
- Unit test verified: [`LoginRateLimiterTest.java`](file:///C:/Users/Dell/.gemini/antigravity/scratch/blueops/backend/src/test/java/com/blueops/auth/LoginRateLimiterTest.java) (lockout and reset verified).

---

## 2. Authorization & Role-Based Access Control (RBAC)

BlueOps enforces strict two-tier Role-Based Access Control: `ROLE_ANALYST` and `ROLE_ADMIN`.

### 2.1 Defense-in-Depth Authorization Layers
1. **HTTP Security Filter Chain:** Configured in `SecurityConfig.java`:
   - `/api/v1/auth/**`: Public access.
   - `/actuator/health`, `/swagger-ui/**`: Public access.
   - `/api/v1/response/actions/*/approve`: `hasRole("ADMIN")`
   - `/api/v1/response/actions/*/reject`: `hasRole("ADMIN")`
   - `/api/v1/response/actions/*/execute`: `hasRole("ADMIN")`
   - `/api/v1/response/actions/*/rollback`: `hasRole("ADMIN")`
   - `DELETE /api/v1/assets/**`: `hasRole("ADMIN")`
   - `DELETE /api/v1/threat-intel/**`: `hasRole("ADMIN")`
   - `DELETE /api/v1/detection-rules/**`: `hasRole("ADMIN")`
   - `PUT /api/v1/detection-rules/**`: `hasRole("ADMIN")`
   - `/api/v1/**`: `authenticated()` (Analyst or Admin)
2. **Method-Level Security:** Enforced via `@EnableMethodSecurity` and `@PreAuthorize` annotations on REST controllers (`ResponseController`, `IncidentController`, `DetectionRuleController`, `AssetController`).

---

## 3. Incident Response Agent Boundary Security (DEF-004)

The BlueOps Response Agent ([`agent.py`](file:///C:/Users/Dell/.gemini/antigravity/scratch/blueops/response-agent/src/agent.py)) executes remediations in the target lab environment. To prevent the agent itself from becoming an attacker vector, the following protections are active:

### 3.1 Strict Allowlist Enforcement
- Remediations restricted strictly to: `BLOCK_IP`, `RESTORE_IP`, `DISABLE_USER`, `ENABLE_USER`, `ISOLATE_HOST`, `RECONNECT_HOST`, `COLLECT_EVIDENCE`.
- Any command or playbook outside this allowlist is immediately rejected with HTTP 400 (`REJECTED_UNAUTHORIZED_ACTION`).

### 3.2 Anti-Tamper HMAC-SHA256 Dispatch
- Requests must include headers: `X-BlueOps-Signature`, `X-BlueOps-Timestamp`, `X-BlueOps-ActionId`.
- Message format: `{timestamp}:{payload}`.
- Secret key loaded dynamically from `RESPONSE_AGENT_SECRET`.
- Verified in [`HmacSignatureServiceTest.java`](file:///C:/Users/Dell/.gemini/antigravity/scratch/blueops/backend/src/test/java/com/blueops/response/HmacSignatureServiceTest.java).

### 3.3 Anti-Replay Protection
- Strict 60-second sliding expiration window (`abs(now - timestamp) <= 60`).
- Nonce deduplication: Every `X-BlueOps-ActionId` is recorded in `PROCESSED_NONCES`. Replayed action IDs return HTTP 409 (`REPLAY_DETECTED`).

### 3.4 Command Injection Prevention
- Input target sanitization regex: `[;&|`$><\r\n]`.
- Attempts to pass shell injection characters or paths exceeding 256 characters return HTTP 400 (`REJECTED_INVALID_PARAMETER`).
- Adversarially verified via [`deceptive_attack_suite.js`](file:///C:/Users/Dell/.gemini/antigravity/scratch/blueops/test-lab/adversary-simulation/deceptive_attack_suite.js) (5/5 boundary tests passing).

---

## 4. Audit Logging & Non-Repudiation (DEF-001)

All security-relevant actions are immutably captured in the PostgreSQL `audit_logs` table:
- **Timestamp:** UTC instant of operation.
- **Actor:** Authenticated username or system principal.
- **Action:** E.g., `INCIDENT_CREATED`, `STATUS_CHANGED`, `ACTION_REQUESTED`, `ACTION_APPROVED`, `ACTION_EXECUTED`, `ACTION_ROLLBACK`, `ASSET_CREATED`, `RULE_STATUS_CHANGED`, `LOGIN_FAILED`, `LOCKED_OUT`.
- **Target Entity:** Entity type and persistent ID.
- **Details JSON:** Structured state changes, previous values, IP addresses, and transition notes.

---

## 5. Vulnerability & Boundary Assessment Summary

| Threat Vector | Mitigation Strategy | Verification Result |
|---|---|:---:|
| **Authentication Brute-Force** | Sliding window rate limiting + 15m lockout | PASSED |
| **JWT Tampering / Forgery** | Cryptographic HMAC-SHA256 signature check | PASSED |
| **Unauthorized Action Execution** | Role-based `@PreAuthorize` + Filter chain | PASSED |
| **Response Agent Command Injection** | Regular expression parameter sanitization | PASSED |
| **Replay Attacks on Response Agent** | 60-second expiration window + Action ID nonces | PASSED |
| **Memory Exhaustion via Query Flooding** | Indexed database queries replacing stream scans | PASSED |
| **Entity Serialization Deadlocks** | `@JsonIgnore` on bi-directional entity relations | PASSED |
