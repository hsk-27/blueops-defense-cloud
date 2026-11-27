# BlueOps — Lab / Demo Deployment Guide

> **Lab / Demo Notice:** The default `docker-compose.yml` topology is scoped for isolated **lab and evaluation** deployments only (plain HTTP `:80` Nginx without TLS termination, single-node OpenSearch with `DISABLE_SECURITY_PLUGIN=true`). Before running with `SPRING_PROFILES_ACTIVE=prod`, supply strong CSPRNG values for `POSTGRES_PASSWORD`, `JWT_SECRET`, `RESPONSE_AGENT_SECRET`, and `BLUEOPS_INGEST_API_KEY` in `.env` and place an external TLS reverse proxy in front of the stack.

## 1. Prerequisites
- Docker Engine 24+ and Docker Compose v2+
- Java 21+ (for native host development)
- Node.js 20+ (for frontend development)
- Host RAM: 8–16 GB physical memory recommended

---

## 2. Lab Stack Deployment (Docker Compose)

### Step 1: Clone & Configure Environment
```bash
cp .env.example .env
# In .env, set strong secrets for POSTGRES_PASSWORD, JWT_SECRET, RESPONSE_AGENT_SECRET, and BLUEOPS_INGEST_API_KEY
```

### Step 2: Launch Supporting Data Infrastructure
```bash
docker compose up -d postgres opensearch opensearch-dashboards fluent-bit
```

Verify services are healthy:
```bash
docker compose ps
```

### Step 3: Launch Application Stack
```bash
docker compose up -d backend frontend response-agent
```

Access Web Interfaces:
- **BlueOps React SOC Dashboard:** `http://localhost:3000`
- **Spring Boot Actuator Health:** `http://localhost:8080/actuator/health`
- **Swagger / OpenAPI Documentation:** `http://localhost:8080/swagger-ui.html`
- **OpenSearch Dashboards:** `http://localhost:5601`

Default Credentials:
| Role | Username | Password |
|---|---|---|
| Admin | `admin` | `Admin@BlueOps2026!` |
| Analyst | `analyst` | `Analyst@BlueOps2026!` |
| Viewer | `viewer` | `Viewer@BlueOps2026!` |

---

## 3. Host-Based Development Mode (Without Container Overhead)

### PostgreSQL & OpenSearch
```bash
docker compose up -d postgres opensearch
```

### Spring Boot Backend
```bash
cd backend
./mvnw spring-boot:run
```

### React SOC Frontend
```bash
cd frontend
npm run dev
```
Accessible at `http://localhost:5173` with automated API proxying to `http://localhost:8080`.
