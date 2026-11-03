#!/usr/bin/env bash
# BlueOps - Local Environment Initialization Script (Linux / macOS)
set -euo pipefail

echo "============================================================"
echo "    BlueOps SOC Platform - Environment Initialization       "
echo "============================================================"

# 1. Environment file check
if [ ! -f ".env" ]; then
    echo "[*] Creating .env from .env.example..."
    cp .env.example .env
else
    echo "[+] Existing .env file detected."
fi

# 2. Check Docker
if command -v docker >/dev/null 2>&1; then
    echo "[+] Docker detected: $(docker --version)"
else
    echo "[-] Warning: Docker not found. Container infrastructure cannot be started automatically."
fi

# 3. Check Java
if command -v java >/dev/null 2>&1; then
    echo "[+] Java detected: $(java -version 2>&1 | head -n 1)"
else
    echo "[-] Warning: Java not detected. JDK 21+ is required for the backend."
fi

# 4. Check Node.js
if command -v node >/dev/null 2>&1; then
    echo "[+] Node.js detected: $(node --version)"
else
    echo "[-] Warning: Node.js not detected. Node 20+ is required for frontend and simulation harness."
fi

echo ""
echo "[+] Initialization complete. You can now start infrastructure via:"
echo "    docker compose up -d postgres opensearch opensearch-dashboards fluent-bit"
echo "============================================================"
