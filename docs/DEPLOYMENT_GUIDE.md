# BlueOps — Enterprise SOC Platform Deployment Guide

## 1. Prerequisites
- Docker Engine 24+ and Docker Compose v2+
- Java 21 or Java 23 (for native host development)
- Node.js 20+ (for frontend development)
- Host RAM: 16 GB physical memory recommended

---

## 2. Central Platform Deployment (Docker Compose)

### Step 1: Clone & Configure Environment
```bash
cd blueops
cp .env.example .env
# Customize passwords and JWT secrets in .env if desired
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
