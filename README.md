# BlueOps — Enterprise Threat Detection & Automated Incident Response Platform

![BlueOps Architecture Overview](https://img.shields.io/badge/Architecture-Modular%20Monolith-blue)
![Java](https://img.shields.io/badge/Java-21%2B%20%7C%2023-orange)
![Spring Boot](https://img.shields.io/badge/Spring%20Boot-3.3%2B-green)
![React](https://img.shields.io/badge/React-18%20TypeScript-blue)
![OpenSearch](https://img.shields.io/badge/OpenSearch-2.x-teal)
![License](https://img.shields.io/badge/License-Apache%202.0-lightgrey)

BlueOps is a deployable Security Operations Center (SOC) platform engineered for real telemetry ingestion, event normalization, Sigma-based threat detection, multi-stage attack correlation, threat intelligence enrichment, and auditable, reversible incident response.

---

## Key Capabilities

1. **Multi-Source Endpoint & Network Telemetry:** Native collection configs for Windows Sysmon, Linux auditd/journald, and Suricata NIDS.
2. **Unified Event Schema:** Normalizes heterogeneous security events into the BlueOps Common Event Schema (v1.0.0).
3. **Deterministic Detection Engine:** 18 Sigma-compatible detection rules covering Windows, Linux, and Network tactics mapped directly to MITRE ATT&CK.
4. **Multi-Stage Attack Correlation:** Four stateful sequence correlation scenarios (e.g. Linux Account Compromise, Windows Process Injection Chains).
5. **Threat Intelligence Enrichment:** High-performance IOC indicator management (IP, Domain, URL, Hash) with automatic matching and confidence scoring.
6. **Analyst-Oriented SOC Dashboard:** React 18 + TypeScript + Tailwind dark-mode interface featuring SOC overview metrics, investigation workspaces, and interactive timelines.
7. **Constrained Response Orchestration:** Cryptographically signed (HMAC-SHA256) reversible response playbooks with multi-tier approval workflows.
8. **Empirical Performance Evaluation:** Benchmarked against Atomic Red Team attack simulations and benign workloads to calculate Precision, Recall, FPR, MTTD, and MTTR.

---

## Architecture Overview

```mermaid
flowchart LR
    VM1[Windows Lab VM\nSysmon] --> FB[Fluent Bit 3.x]
    VM2[Linux Lab VM\nauditd] --> FB
    NET[Virtual Network\nSuricata] --> FB
    FB --> OS[(OpenSearch 2.x\nSecurity Analytics)]
    OS --> SYNC[Finding Adapter]
    SYNC --> BO[BlueOps Backend\nSpring Boot 3]
    BO <--> PG[(PostgreSQL 16)]
    BO --> UI[React SOC UI]
    BO -->|Signed Action| RA[Response Agent]
```

---

## Directory Structure

```text
blueops/
├── infrastructure/       # Docker Compose, OpenSearch, Fluent Bit, Suricata, Sysmon/Auditd configs
├── detection-rules/      # Sigma rules (Windows, Linux, Network) and correlation scenarios
├── backend/              # Spring Boot 3 modular monolith (Java 21+)
├── frontend/             # React 18 + TypeScript + Tailwind CSS SOC dashboard
├── response-agent/       # Restricted, HMAC-authenticated Python response agent
├── test-lab/             # Atomic Red Team test scenarios and validation fixtures
├── scripts/              # Automated setup, verification, and benchmark scripts
└── docs/                 # Complete engineering design and deployment documentation
```

---

## Quick Start Guide

### Prerequisites
- Java 21+ (Java 23 supported)
- Node.js 20+
- Docker Desktop with Compose support
- 16 GB RAM host recommended

### 1. Start Infrastructure
```bash
cp .env.example .env
docker compose up -d postgres opensearch opensearch-dashboards fluent-bit
```

### 2. Start Backend
```bash
cd backend
./mvnw spring-boot:run
```

### 3. Start Frontend
```bash
cd frontend
npm install
npm run dev
```

Visit `http://localhost:3000` to access the BlueOps SOC Dashboard.

---

## License
Apache License 2.0. See [LICENSE](LICENSE) for details.
