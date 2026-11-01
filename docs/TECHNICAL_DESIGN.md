# BlueOps — Technical Design Specification

## 1. Modular Monolith Architecture
BlueOps is engineered as a high-performance modular monolith built on **Spring Boot 3.3.5 / Java 21+** and **React 18 / TypeScript**.
It deliberately avoids the operational complexity of distributed microservices, service meshes, and Kafka to remain deployable on a 16 GB laptop host while providing strict bounded contexts.

### Module Boundaries
1. `com.blueops.auth`: Authentication, JWT issuance, token rotation, and credential validation.
2. `com.blueops.users`: Identity persistence, roles (`ROLE_ADMIN`, `ROLE_ANALYST`, `ROLE_VIEWER`).
3. `com.blueops.assets`: Monitored endpoint inventory, telemetry health timestamps, status lifecycle.
4. `com.blueops.detections`: Sigma rule catalog, status management, detection metadata.
5. `com.blueops.findings`: OpenSearch Finding Adapter, telemetry ingestion, finding deduplication.
6. `com.blueops.incidents`: Finite state machine, investigation timeline, triage notes, assignments.
7. `com.blueops.threatintel`: IOC indicator storage, CSV bulk ingestion, regex validation, telemetry matching.
8. `com.blueops.response`: Constrained response playbooks, HMAC-SHA256 signature generator, reversal tracking.
9. `com.blueops.audit`: Administrative and security event audit trail.
10. `com.blueops.reporting`: Database-backed SOC overview metrics, MTTD/MTTR calculations, ATT&CK matrix.

---

## 2. Ingestion & Search Architecture
- **Raw Telemetry Storage:** OpenSearch 2.13+ manages event streams in `blueops-events-YYYY.MM.DD`.
- **Finding Ingestion:** Security Analytics detectors generate findings into `blueops-findings-*`.
- **Fault-Tolerant Finding Adapter:** If the OpenSearch cluster is temporarily unreachable or starting up, the Spring Boot backend catches network timeouts and gracefully serves findings from a synchronized memory cache without blocking analyst operations.
- **Dead-Letter Queue:** Malformed or unparseable events from Fluent Bit are routed to `blueops-dlq-*` with detailed parser error context.

---

## 3. Reliability & Concurrency
- Optimistic locking and transactional consistency via Spring `@Transactional`.
- Stateless REST session management using signed HMAC-SHA256 JWT tokens.
- Nonces and timestamps incorporated in response execution to prevent replay attacks.
