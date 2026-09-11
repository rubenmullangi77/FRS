#!/usr/bin/env bash
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SERVER_BIN="${SCRIPT_DIR}/build_linux/bin/forensivault_server"

echo "======================================================================"
echo "          FORENSIVAULT FORENSIC INVESTIGATION PLATFORM"
echo "               Linux Desktop Launcher (Vite + C++)"
echo "======================================================================"
echo ""

if [ ! -f "${SERVER_BIN}" ]; then
    echo "[*] ForensiVault C++ server not found. Running build.sh first..."
    bash "${SCRIPT_DIR}/build.sh"
fi

if [ ! -d "${SCRIPT_DIR}/frontend/node_modules" ]; then
    echo "[*] Frontend dependencies not found. Running 'npm install' in frontend/..."
    (cd "${SCRIPT_DIR}/frontend" && npm install)
fi

echo "[*] Launching Native C++ ForensiVault API Server (Port 8765)..."
"${SERVER_BIN}" --port 8765 &
SERVER_PID=$!

cleanup() {
    echo ""
    echo "[*] Shutting down ForensiVault server (PID ${SERVER_PID})..."
    kill "${SERVER_PID}" 2>/dev/null || true
    exit 0
}
trap cleanup SIGINT SIGTERM EXIT

echo "[*] Launching ForensiVault React Forensic Dashboard..."
cd "${SCRIPT_DIR}/frontend"
npm run dev -- --host 127.0.0.1 --port 5173
