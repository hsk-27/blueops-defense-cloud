# AI Agent & Operator Safety Guardrails (`blueops-defense-cloud`)

This file defines **mandatory, non-negotiable safety rules** for **any AI coding assistant, autonomous agent (including Antigravity), script, or human operator** modifying or running this repository on a developer's laptop.

---

## 1. Non-Negotiable Laptop Protection Rule

BlueOps is engineered so that **all defensive containment actions and adversary simulations remain strictly hypothetical** (`HYPOTHETICAL_LAB_SANDBOX` / `SIMULATION`) when run on a user's workstation.

**DO NOT** enable, remove, or bypass any of the following settings or protections on the user's laptop:

1. **Backend Live Execution Locks:**
   - `blueops.response.allow-live-execution` / `BLUEOPS_ALLOW_LIVE_EXECUTION` (must stay `false`)
   - `blueops.response-agent.simulation-mode` / `RESPONSE_AGENT_SIMULATION_MODE` (must stay `true`)
   - [ResponsePolicyEngine.java](backend/src/main/java/com/blueops/response/ResponsePolicyEngine.java), [ResponseOrchestrationService.java](backend/src/main/java/com/blueops/response/ResponseOrchestrationService.java), and [ResponsePolicyValidator.java](backend/src/main/java/com/blueops/response/ResponsePolicyValidator.java) simulation downgrades, fail-closed target registry checks, and loopback/infrastructure denylists (`127.0.0.1`, `::1`, `localhost`, gateways, DNS).
2. **Python Response Agent Hypothetical Drivers:**
   - `EXECUTION_MODE` (must stay `SIMULATION`) and `BLUEOPS_ALLOW_LIVE_HOST_DISRUPTION` (must stay `false`) in [agent.py](response-agent/src/agent.py), `.env.example`, and `docker-compose.yml`.
   - [drivers.py](response-agent/src/drivers.py) deliberately contains **zero `subprocess` / OS-mutating calls** (`netsh`, `iptables`, `net user`, `usermod`, process termination). **Do NOT add live OS subprocess/syscall execution to `drivers.py` or anywhere else in this repository.**
3. **Host Safety & Workspace Bounds:**
   - Never delete, modify, or probe files, firewall rules, registry keys, user accounts, network interfaces, or system services outside `blueops-defense-cloud`.

---

## 2. Only Permitted Exception Rule for Any AI

An AI assistant or automation tool may modify or relax the hypothetical/simulation settings above **ONLY IF at least one of these two strict conditions holds and is verified:**

1. **Zero Risk to the Laptop:** The change runs strictly inside a dedicated, isolated, disposable virtual machine or network-isolated sandbox explicitly approved by the user, **cannot reach or mutate the developer's laptop OS/network/accounts**, and keeps all host protections intact by default in the repository.
2. **Safe, Working Workaround Without Extra Risky Apps:** Instead of enabling live OS execution or requiring the user to attach external apps/daemons, implement a **self-contained hypothetical, in-memory, standard-library, or mock workaround** that works reliably (for example: Spring Boot `dev` profile H2/OpenSearch fallback, `MockRestServiceServer` contract tests, or `response-agent`'s zero-dependency Python stdlib HTTP fallback).

If neither condition holds, **stop and keep the setting locked in hypothetical/simulation mode**.

---

## 3. Baseline Local Execution (No Extra Apps Required)

- **Backend:** Spring Boot 3.3.5 + Maven (`cd backend && .\mvnw.cmd spring-boot:run`) — uses embedded H2 PostgreSQL-mode, Flyway `V1`–`V5`, in-memory OpenSearch fallback, and in-JVM `SimulationResponseAdapter`.
- **Frontend:** React + Vite (`cd frontend && npm run dev`).
- **All Automated Suites:** `.\scripts\testing\run_all_tests.ps1` (runs Backend JUnit 5, Frontend Vitest/Vite build, Response Agent Pytest with built-in stdlib fallback, and JS smoke scripts).
