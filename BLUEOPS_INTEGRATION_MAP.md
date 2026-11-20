# BLUEOPS TECHNOLOGY INTEGRATION MAP & ARCHITECTURAL DECISION MATRIX

**Document Version:** 2.0.0  
**Classification:** Defensive Technology Architecture & Dependency Governance  
**System Document ID:** BLUEOPS-MAP-2026-001  

---

## 1. INTEGRATION PHILOSOPHY: REUSE OVER REINVENTION

BlueOps strictly adheres to **Architectural Invariant 3**: *Do not reinvent infrastructure that mature, existing technologies already provide adequately.*

Rather than constructing custom event brokers, custom search engines, or custom forwarding agents from scratch, BlueOps functions as an **integrating, orchestrating, and policy-governing platform**. Engineering effort is concentrated where off-the-shelf software fails to deliver:
1. Cross-telemetry event normalization into the Common Event Schema (CES v1.0.0).
2. Dynamic stream-based Sigma condition AST evaluation with zero external query overhead.
3. Multi-stage attack chain correlation connecting network, host, and authentication anomalies.
4. Cryptographically authenticated, policy-bounded defensive response orchestration.

---

## 2. TECHNOLOGY INVENTORY & SELECTION MATRIX

| Operational Domain | Candidate Technologies Evaluated | Selected Technology | Architectural Role | Integration Strategy | Disposition |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Telemetry Forwarding** | Fluent Bit, Vector, Logstash, OpenTelemetry Collector | **Fluent Bit (3.0.4)** | Ingestion broker for syslog (UDP/TCP: 5140), parsing, and forwarding to backend REST API. | **Integrate** | Approved & Configured |
| **Relational Storage** | PostgreSQL, MySQL, SQLite, CockroachDB | **PostgreSQL (16-Alpine)** | Authoritative system of record for Incidents, Users, RBAC, Assets, Playbooks, and Audit Logs. | **Integrate** | Approved & Implemented |
| **Log & Finding Search** | OpenSearch, Elasticsearch, ClickHouse, MongoDB | **OpenSearch (2.13.0)** | Inverted-index document store for fast telemetry retrieval, free-text investigation, and finding analytics. | **Integrate** | Approved & Implemented |
| **Detection Engine** | PySigma, ElastAlert2, Custom Stream AST Evaluator | **Custom Sigma Stream AST Evaluator + OpenSearch Queries** | Dynamic in-memory stream evaluation for single events; hybrid query translation for historical log analysis. | **Implement & Wrap** | In Active Use (AST evaluator requires aggregation window refinement) |
| **Host Response Daemon** | Custom Python Agent, Osquery, SaltStack, Ansible | **Custom Python Response Daemon (FastAPI)** | Minimal-footprint, locked-down endpoint daemon executing approved containment commands with HMAC-SHA256 authentication. | **Implement** | Approved & Implemented |
| **Security & Auth** | Spring Security 6 + JJWT, Keycloak, Auth0, Apache Shiro | **Spring Security 6 + JJWT (0.12.5)** | In-process JWT authentication, stateless session management, PBKDF2/BCrypt hashing, and role-based route authorization. | **Integrate** | Approved & Implemented |
| **Frontend Framework** | React 18, Vue 3, Angular, Svelte | **React 18 + Vite + TailwindCSS** | High-performance, single-page SOC analyst interface with real-time telemetry streaming and incident triage. | **Integrate** | Approved & Implemented |
| **Database Migrations** | Flyway, Liquibase, Hibernate DDL Auto | **Flyway (10.x)** | Deterministic version-controlled relational schema migrations (`db/migration/V*`). | **Integrate** | Approved & Implemented |

---

## 3. DEEP DIVE: SUBSYSTEM INTEGRATION CONTRACTS

### 3.1 Telemetry Collection & Transport
- **Selected:** Fluent Bit (`image: fluent/fluent-bit:3.0.4`)
- **Port Allocations:**
  - `5140/udp` & `5140/tcp`: Syslog ingestion from Linux rsyslog and network appliances.
  - `24224/tcp`: Forward protocol for containerized collectors.
  - `2020/tcp`: Internal HTTP monitoring and metrics endpoint.
- **Contract with BlueOps Backend:**
  Fluent Bit outputs parsed events via HTTP POST to `http://backend:8080/api/v1/telemetry/ingest`.
- **Rejected Alternatives:**
  - *Logstash:* Rejected due to excessive memory footprint (JVM overhead of >1 GB compared to Fluent Bit's ~20 MB).
  - *Vector:* High-quality alternative, but Fluent Bit has broader native parsing support for standard Linux syslog, Windows event log outputs, and Suricata EVE streams in enterprise SOC environments.

### 3.2 Event Storage & Dual-Store Ownership
To avoid data divergence, BlueOps strictly establishes **authoritative domain boundaries**:

| Domain Entity | Authoritative Store | Secondary / Cached In | Synchronization Mechanism | Failure Mode Handling |
| :--- | :--- | :--- | :--- | :--- |
| **User & RBAC** | PostgreSQL | In-Memory Spring Security Cache | Authenticated on every request via JWT claims | Fail Closed: 401 Unauthorized |
| **Incidents & Notes** | PostgreSQL | OpenSearch (Search index) | Asynchronous indexing on create/update | Primary DB guarantees ACID; search index sync is non-blocking |
| **Response Actions & Executions**| PostgreSQL | OpenSearch (Audit record) | Direct write on action state change | Authoritative record in PostgreSQL; agent errors logged directly |
| **Playbooks & Policies** | PostgreSQL | None | Direct query on startup and execution | Fail Closed: Action rejected if playbook not found |
| **Raw Events & CES Telemetry** | OpenSearch (`blueops-events-*`)| In-Memory Ring Buffer (1,000 events)| Batch ingest pipeline | If OpenSearch fails, recent events are retained in ring buffer; DLQ captures overflow |
| **Security Findings** | OpenSearch (`blueops-findings-*`)| In-Memory Concurrent HashMap (1,000 findings)| Written upon detection evaluation | If OpenSearch is down, findings are held in memory to allow correlation and incident creation |

### 3.3 Detection Engine Architecture: Hybrid Evaluation
BlueOps does not attempt to reimplement the entire Sigma compiler stack from scratch. Instead, it adopts a **pragmatic hybrid model**:

1. **In-Memory Stream Evaluation (`SigmaDetectionEvaluator` + `SigmaConditionEvaluator`):**
   - For real-time, low-latency detection as events flow into `/api/v1/telemetry/ingest`.
   - Uses an internal Boolean AST compiler to evaluate logical conditions (`and`, `or`, `not`, parentheses) and field matchers (`startswith`, `endswith`, `contains`, `re`).
   - *Limitation & Roadmap:* Multi-event aggregations (`| count() > N by entity`) currently strip the aggregation modifier in the single-event stream evaluator, causing premature triggers on single failed events. Milestone M2 will route aggregation rules to a dedicated sliding-window state store.
2. **OpenSearch Query Translation (Historical Threat Hunting):**
   - For retrospective threat hunting across historical telemetry stored in `blueops-events-*`.
   - Utilizes standard Lucene / OpenSearch Query DSL translated from Sigma detection selections.

### 3.4 Response Agent Integration & Execution Boundary
- **Selected:** Python 3.10+ FastAPI Daemon running on target endpoints.
- **Protocol:** HTTP REST over mutual TLS (or internal network) with **HMAC-SHA256 application-layer signature**.
- **Security Headers Required:**
  - `X-Signature-SHA256`: Hex-encoded HMAC-SHA256 hash of `HTTP_METHOD + PATH + TIMESTAMP + NONCE + BODY`.
  - `X-Timestamp`: Unix epoch millisecond timestamp (rejected if $|T_{now} - T_{req}| > 60,000\text{ ms}$).
  - `X-Nonce`: Cryptographic UUID v4 (cached in a sliding TTL window to reject duplicate executions).
- **Execution Drivers (`response-agent/src/drivers.py`):**
  - **Linux Driver:** `iptables` / `ufw` for network containment; `usermod -L` / `passwd -l` for account freezing.
  - **Windows Driver:** `netsh advfirewall` for port/IP blocking; `net user /active:no` for account locking.
  - **Simulation Driver:** Logs intent, validates arguments against regular expressions, and returns simulated execution telemetry without modifying OS kernel state.

### 3.5 Threat Intelligence & IOC Integration
- **Selected:** Internal Relational IOC Registry (`com.blueops.threatintel`) + External STIX/TAXII Ingestion Adapter (Roadmap M5).
- **Supported Indicator Types:** `IP_ADDRESS`, `DOMAIN_NAME`, `FILE_HASH_SHA256`, `FILE_HASH_MD5`.
- **Contract:** Matching occurs during `DetectionEvaluationService.evaluate()`. Matching indicators generate findings tagged with MITRE ATT&CK technique `T1071` (Application Layer Protocol) or `T1584` (Compromise Infrastructure).

---

## 4. REJECTED TECHNOLOGIES & DETAILED RATIONALE

### 1. Apache Kafka / RabbitMQ (Deferred for Core M0-M3)
- **Rationale for Deferral:** While Kafka is the standard for multi-gigabyte/second enterprise event streaming, introducing a Kafka cluster (or Zookeeper/Kraft) introduces 3 additional containers, 4 GB of baseline memory overhead, and substantial operational maintenance. BlueOps core currently utilizes an in-process, non-blocking Ring Buffer and synchronized Dead-Letter Queue (DLQ). Message broker adapters will be introduced as an optional enterprise extension in Milestone M7.

### 2. Full Microservices Split (Rejected)
- **Rationale for Rejection:** Splitting Telemetry, Detection, Incident Management, and Response into 4 independent microservices would require distributed tracing, distributed transactions (Saga pattern), network serialization overhead, and multiple deployment pipelines. The system is designed as a **Modular Monolith** within a single JVM, providing nanosecond in-memory event passing between normalization, detection, and correlation.

### 3. Unrestricted Shell Execution on Response Agent (Rejected)
- **Rationale for Rejection:** An endpoint agent that executes arbitrary shell strings sent from the backend is an extreme security liability (Remote Code Execution by design). BlueOps strictly confines the agent to a hardcoded catalogue of validated parameter actions (`block_ip`, `restore_ip`, `disable_user`, `enable_user`). All inputs are sanitized using strict regexes before execution.

---

## 5. DEPENDENCY AUDIT & MINIMAL JUSTIFICATION

Every dependency in `backend/pom.xml`, `frontend/package.json`, and `response-agent/requirements.txt` is maintained under strict governance:

- **Spring Boot 3.2.0:** Base application framework, Web, Security, Data JPA, Validation, Actuator.
- **jjwt-api 0.12.5:** Clean, zero-dependency cryptographic JWT implementation.
- **SnakeYAML 2.2:** Standards-compliant YAML parser for Sigma rule loading.
- **Flyway Core 10.4.1:** Automated database schema migration.
- **FastAPI 0.110.0 + Uvicorn 0.28.0:** Lightweight, asynchronous Python daemon for response execution.
- **React 18 + Vite 5 + Lucide React:** Fast, accessible frontend UI with minimal bundle size.
