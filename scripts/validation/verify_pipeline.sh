#!/usr/bin/env bash
# BlueOps - Telemetry Pipeline Verification Script (Linux / macOS)
set -euo pipefail

BACKEND_URL="${BLUEOPS_BACKEND_URL:-http://localhost:8080}"
echo "[*] Verifying BlueOps Backend connectivity at: $BACKEND_URL"

# Health Check
HEALTH_STATUS=$(curl -s -o /dev/null -w "%{http_code}" "$BACKEND_URL/actuator/health" || echo "FAIL")
if [ "$HEALTH_STATUS" = "200" ]; then
    echo "[+] Backend Health: ONLINE"
else
    echo "[-] Backend Health: OFFLINE or UNREACHABLE (HTTP $HEALTH_STATUS)"
fi

# Verification of sample Sysmon ingestion
echo "[*] Sending sample verification telemetry payload..."
RESPONSE_CODE=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$BACKEND_URL/api/v1/telemetry/ingest" \
    -H "Content-Type: application/json" \
    -d '{"provider":"Sysmon","EventID":1,"hostname":"WIN-TEST-01","CommandLine":"whoami.exe","user":"analyst"}' || echo "FAIL")

if [ "$RESPONSE_CODE" = "200" ] || [ "$RESPONSE_CODE" = "201" ]; then
    echo "[+] Telemetry Pipeline: INGESTION SUCCESSFUL (HTTP $RESPONSE_CODE)"
else
    echo "[-] Telemetry Pipeline: FAILED (HTTP $RESPONSE_CODE)"
fi
