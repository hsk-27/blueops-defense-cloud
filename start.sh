#!/usr/bin/env bash
# BlueOps Local Start Script (Linux / macOS)
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT_DIR"

echo "============================================================"
echo "          BlueOps SOC Platform - Local Startup               "
echo "============================================================"

if [ ! -f ".env" ]; then
    echo "[*] Creating .env from .env.example..."
    cp .env.example .env
fi

echo "[*] Starting Docker infrastructure (PostgreSQL, OpenSearch, Fluent Bit)..."
docker compose up -d postgres opensearch opensearch-dashboards fluent-bit

echo "[*] Starting Backend in background..."
(cd "$ROOT_DIR/backend" && ./mvnw spring-boot:run) &
BACKEND_PID=$!

echo "[*] Starting Frontend in background..."
(cd "$ROOT_DIR/frontend" && npm run dev) &
FRONTEND_PID=$!

echo "============================================================"
echo "BlueOps is launching:"
echo "  - Frontend: http://localhost:3000"
echo "  - Backend API: http://localhost:8080"
echo "  - Swagger UI: http://localhost:8080/swagger-ui.html"
echo "  - OpenSearch Dashboards: http://localhost:5601"
echo "============================================================"
echo "Press Ctrl+C to terminate services."

trap "kill $BACKEND_PID $FRONTEND_PID 2>/dev/null || true; exit" INT TERM
wait
