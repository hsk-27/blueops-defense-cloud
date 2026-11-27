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

# Authenticate
echo "[*] Authenticating with BlueOps Backend..."
TOKEN=""
ADMIN_USER="${BLUEOPS_ADMIN_USERNAME:-admin}"
ADMIN_PASS="${BLUEOPS_ADMIN_PASSWORD:-Admin@BlueOps2026!}"
AUTH_RESP=$(curl -s -X POST "$BACKEND_URL/api/v1/auth/login" \
    -H "Content-Type: application/json" \
    -d "{\"username\":\"$ADMIN_USER\",\"password\":\"$ADMIN_PASS\"}" || true)

if echo "$AUTH_RESP" | grep -q '"accessToken"'; then
    TOKEN=$(echo "$AUTH_RESP" | grep -o '"accessToken":"[^"]*' | cut -d'"' -f4)
    echo "[+] Authentication: SUCCESSFUL (Access token acquired)"
else
    echo "[-] Authentication: FAILED (Access token not acquired)"
fi

# Verification of sample Sysmon ingestion
echo "[*] Sending sample verification telemetry payload..."
AUTH_HEADER=()
if [ -n "$TOKEN" ]; then
    AUTH_HEADER=(-H "Authorization: Bearer $TOKEN")
fi

RESPONSE_CODE=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$BACKEND_URL/api/v1/telemetry/ingest" \
    -H "Content-Type: application/json" \
    "${AUTH_HEADER[@]}" \
    -d '{"provider":"Sysmon","EventID":1,"hostname":"WIN-TEST-01","CommandLine":"whoami.exe","user":"analyst"}' || echo "FAIL")

if [ "$RESPONSE_CODE" = "200" ] || [ "$RESPONSE_CODE" = "201" ]; then
    echo "[+] Telemetry Pipeline: INGESTION SUCCESSFUL (HTTP $RESPONSE_CODE)"
else
    echo "[-] Telemetry Pipeline: FAILED (HTTP $RESPONSE_CODE)"
fi
