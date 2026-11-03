# Contributing to BlueOps

Thank you for your interest in contributing to **BlueOps — Enterprise Threat Detection & Automated Incident Response Platform**!

BlueOps is an open-source, deterministic miniature Security Operations Center (SOC) platform engineered for enterprise telemetry ingestion, Sigma detection rules, multi-stage attack correlation, and cryptographically verified, reversible incident response.

---

## 1. Code of Conduct

All contributors and maintainers are expected to adhere to our [Code of Conduct](CODE_OF_CONDUCT.md). Please report any unacceptable behavior according to the instructions in that document.

---

## 2. Ways to Contribute

- **Detection Engineering:** Contribute new Sigma detection rules mapped to MITRE ATT&CK techniques under `detection-rules/sigma/`.
- **Adversary Simulations:** Add new controlled Atomic Red Team test scenarios under `test-lab/`.
- **Backend Engineering:** Enhance event normalization, correlation engine algorithms, or response orchestration in `backend/`.
- **Frontend / UX:** Improve the React + Tailwind SOC analyst console, investigation timeline, or telemetry inspector in `frontend/`.
- **Bug Reports & Fixes:** Identify and fix bugs, security issues, or performance bottlenecks.
- **Documentation:** Improve setup guides, architectural runbooks, or academic reproducibility materials in `docs/`.

---

## 3. Development Workflow

### Prerequisites
- **Java:** JDK 21+ (Java 23 supported)
- **Build Tool:** Maven (wrapper `./mvnw` provided)
- **Node.js:** Node.js 20+ and npm
- **Python:** Python 3.11+
- **Docker:** Docker Desktop with Compose support

### Setup Local Environment
```bash
# 1. Clone repository
git clone https://github.com/your-org/blueops.git
cd blueops

# 2. Configure environment
cp .env.example .env

# 3. Start local infrastructure
docker compose up -d postgres opensearch opensearch-dashboards fluent-bit

# 4. Run backend tests
cd backend
./mvnw clean test

# 5. Run frontend tests and build
cd ../frontend
npm install
npm test
npm run build
```

---

## 4. Detection Engineering Guidelines

When contributing detection rules:
1. Rules must reside in `detection-rules/sigma/` in standard Sigma YAML format.
2. Must specify accurate MITRE ATT&CK Tactic and Technique IDs (e.g. `T1059.001`).
3. Must maintain deterministic criteria (avoiding unbounded regexes or non-reproducible conditions).
4. Must include false positive analysis and benign exclusion logic.
5. Must be tested against both malicious payloads and benign baseline events in `test-lab/`.

---

## 5. Security & Response Guidelines

1. **Deterministic Security:** Do not introduce autonomous LLM execution into core response authorization.
2. **Reversibility:** Every automated remediation playbook must provide a corresponding rollback action.
3. **Defense-in-Depth:** All incoming action targets must be sanitized against shell metacharacters (`[;&|`$><\r\n]`).
4. **Non-Repudiation:** Any state modification must log an audit record via `AuditService.recordEvent()`.

---

## 6. Pull Request Process

1. Fork the repository and create your feature branch from `master` (`git checkout -b feature/my-enhancement`).
2. Ensure all backend tests pass: `./mvnw test`.
3. Ensure all frontend tests pass and build succeeds: `npm test && npm run build`.
4. Ensure adversary simulation passes: `node test-lab/run_simulations.js`.
5. Open a Pull Request referencing any related issues and following the [Pull Request Template](.github/PULL_REQUEST_TEMPLATE.md).
