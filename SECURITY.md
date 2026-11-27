# BlueOps Security Policy & Architecture Security Controls

**Document ID:** BLUEOPS-SEC-001  
**Classification:** Operational Security Policy & Defensive Architecture Standards  
**Version:** 1.2.0  
**Status:** Mandatory Engineering Standard  

---

## 1. Supported Versions

We provide security updates and patches for the following versions of BlueOps:

| Version | Supported          |
| :---    | :---               |
| 1.2.x   | :white_check_mark: |
| 1.1.x   | :white_check_mark: |
| < 1.1.0 | :x:                |

---

## 2. Responsible Vulnerability Disclosure

The BlueOps team takes security vulnerabilities seriously. We appreciate efforts to responsibly disclose findings.

### Reporting Channels
**DO NOT report security vulnerabilities through public GitHub issues.**

Please report security vulnerabilities via:
- **Private Vulnerability Reporting:** GitHub [Security Advisories](https://github.com/hsk-27/blueops-defense-cloud/security/advisories/new).
- **Security Operations Email:** `security@blueops.lab`

### Report Requirements
1. **Description:** Attack vector, reproduction payload, and affected component.
2. **Component Affected:** Backend, Frontend, Response Agent, Telemetry Ingestion, or Detection Rules.
3. **Reproduction Proof-of-Concept:** Non-destructive PoC demonstrating the flaw.
4. **Environment:** OS, Java, Node, Python versions.

---

## 3. Core Security Principles & Architectural Controls

### 3.1. Cryptographic Key Management & Entropy Standards
- **Token Signing:** All JWT access and refresh tokens must be signed using HMAC-SHA256 with keys containing **minimum 256 bits (32 bytes)** of genuine cryptographic entropy.
- **Entropy Calculation:** Secret evaluation must measure **Shannon Information Entropy** ($H(X) = -\sum P(x_i) \log_2 P(x_i)$) across the key space:
  - Minimum acceptable Shannon entropy is **3.8 bits per character/byte**.
  - Repetitive strings (e.g., `aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa`), simple sequences (`12345678901234567890...`), or repeated words are rejected unconditionally.
- **Startup Validation:** In all production-tier profiles (`prod`, `production`, `prd`, `live`), the backend executes `SecurityStartupValidator` at startup. If an insecure, default, blacklisted, or low-entropy key is detected, the application **immediately terminates** boot with a `SecurityException`.

### 3.2. Response Agent Security Boundary
The host-level response agent operates under strict boundary defenses:
1. **Cryptographic Authenticity:** Every incoming request must provide an `X-BlueOps-Signature` computed as `HMAC-SHA256(SECRET_KEY, f"{timestamp}:{raw_payload}")`. Signatures are evaluated using constant-time equality comparisons (`hmac.compare_digest`) to prevent timing side-channel attacks.
2. **Sliding-Window Anti-Replay:**
   - The payload timestamp must be within a **60-second sliding window** (`|current_time - timestamp| <= 60`).
   - Every request requires a unique `action_id` (UUIDv4 nonce).
   - Nonces are tracked with a sliding Time-To-Live (TTL) cache. Entries expire only when their corresponding 60-second validity window has lapsed, preventing replay attacks across cache cleanups.
3. **Command & Argument Injection Defense:**
   - All actions in [agent.py](response-agent/src/agent.py) validate catalog contracts (`ACT-001`–`ACT-007` / `P001`–`P007`) and reject shell metacharacters (`;&|$\`><\r\n`), whitespace, and leading hyphens (`-`) before reaching the driver layer.
   - [drivers.py](response-agent/src/drivers.py) executes **zero OS subprocesses or shell commands** (`subprocess` removed; firewall, account, and host containment actions are purely hypothetical `HYPOTHETICAL_LAB_SANDBOX` models).
4. **Action Allowlisting:** The agent accepts only explicitly allowlisted structured actions (`ACT-001`–`ACT-007` / `P001`–`P007`):
   - `BLOCK_IP`, `DISABLE_USER`, `ISOLATE_HOST`, `RESTORE_IP`, `ENABLE_USER`, `RECONNECT_HOST`, `COLLECT_EVIDENCE`
   Catalog `ACT-008` and arbitrary shell execution requests are rejected unconditionally (`501 UNSUPPORTED_ACTION` backend-side, `400 REJECTED_UNAUTHORIZED_ACTION` agent-side).

### 3.3. Hypothetical Containment & Laptop Safety Guard
- **Hypothetical-Only Drivers:** Both [SimulationResponseAdapter.java](backend/src/main/java/com/blueops/response/SimulationResponseAdapter.java) and [drivers.py](response-agent/src/drivers.py) execute exclusively in hypothetical/simulated sandbox mode (`SIMULATION` / `HYPOTHETICAL_LAB_SANDBOX`) without modifying `iptables`, Windows Firewall, user accounts, or active processes.
- **Locked Defaults:** `BLUEOPS_ALLOW_LIVE_EXECUTION=false`, `RESPONSE_AGENT_SIMULATION_MODE=true`, `EXECUTION_MODE=SIMULATION`, and `BLUEOPS_ALLOW_LIVE_HOST_DISRUPTION=false`.

### 3.4. Role-Based Access Control (RBAC)
- All endpoints enforce strict Spring Security filter chains and `@PreAuthorize` method annotations:
  - `ROLE_VIEWER`: Read-only access (`GET`) to telemetry, findings, incidents, and SOAR queues/catalogs.
  - `ROLE_ANALYST`: Investigation updates plus SOAR policy preview, proposal creation, and proposal cancellation.
  - `ROLE_ADMIN`: Rule reloads, destructive deletes, and SOAR proposal approval, denial, execution, and rollback (subject to Separation of Duties on `HIGH`/`CRITICAL` proposals).

---

## 4. AI Agent & Automation Safety Directive

Per [AGENTS.md](AGENTS.md), **any AI coding assistant or operator script working on this repository must NOT relax or override simulation/hypothetical response settings or introduce OS-mutating commands** unless it is strictly proven **not to threaten the user's laptop** (e.g., an isolated disposable VM explicitly approved by the user) **or** provides a verified non-host-mutating workaround that works locally.
