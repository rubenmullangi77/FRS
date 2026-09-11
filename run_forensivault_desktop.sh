#!/usr/bin/env bash
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "====================================================================="
echo "      FORENSIVAULT - Professional Digital Forensics Workstation"
echo "                Smart India Hackathon 2026 Edition"
echo "====================================================================="
echo ""
echo "[*] Checking ForensiVault backend on port 8765..."

BACKEND_PID=""

if ! curl -s http://127.0.0.1:8765/api/status >/dev/null 2>&1; then
    if python3 -c "import fastapi, uvicorn" >/dev/null 2>&1; then
        echo "[*] Starting ForensiVault Python FastAPI backend (Port 8765)..."
        python3 -m uvicorn backend_fastapi.main:app --host 127.0.0.1 --port 8765 &
        BACKEND_PID=$!
    elif [ -f "${SCRIPT_DIR}/build_linux/bin/forensivault_server" ]; then
        echo "[*] Starting ForensiVault Native C++ server (Port 8765)..."
        "${SCRIPT_DIR}/build_linux/bin/forensivault_server" --port 8765 &
        BACKEND_PID=$!
    else
        echo "[*] Starting ForensiVault Python Bridge server (Port 8765)..."
        python3 "${SCRIPT_DIR}/backend_server.py" &
        BACKEND_PID=$!
    fi
    sleep 2
else
    echo "[+] ForensiVault backend is already active and online on port 8765."
fi

cleanup() {
    if [ -n "${BACKEND_PID}" ]; then
        echo "[*] Terminating ForensiVault backend (PID ${BACKEND_PID})..."
        kill "${BACKEND_PID}" 2>/dev/null || true
    fi
    if [ -n "${VITE_PID}" ]; then
        echo "[*] Terminating Vite frontend (PID ${VITE_PID})..."
        kill "${VITE_PID}" 2>/dev/null || true
    fi
    exit 0
}
trap cleanup SIGINT SIGTERM EXIT

cd "${SCRIPT_DIR}/frontend"

if [ ! -d "${SCRIPT_DIR}/frontend/node_modules" ]; then
    echo "[*] Frontend dependencies not found. Installing via 'npm install'..."
    npm install
fi

echo "[*] Checking Vite frontend on port 5173..."
VITE_PID=""
if ! curl -s http://127.0.0.1:5173 >/dev/null 2>&1; then
    echo "[*] Starting Vite frontend server in background (Port 5173)..."
    npm run dev -- --host 127.0.0.1 --port 5173 >/dev/null 2>&1 &
    VITE_PID=$!
    
    echo "[*] Waiting for Vite frontend to be ready..."
    for i in {1..30}; do
        if curl -s http://127.0.0.1:5173 >/dev/null 2>&1; then
            echo "[+] Vite frontend is online and responding."
            break
        fi
        sleep 0.5
    done
else
    echo "[+] Vite frontend server is active and online on port 5173."
fi

echo ""
echo "[*] Launching ForensiVault Desktop Application (Electron)..."
echo "[*] Demo Credentials: Username: Ruben  |  Password: rube"
echo ""

ELECTRON_BIN="${SCRIPT_DIR}/frontend/node_modules/.bin/electron"
if [ -x "${ELECTRON_BIN}" ]; then
    "${ELECTRON_BIN}" --disable-features=Vulkan electron/main.cjs
else
    npx electron --disable-features=Vulkan electron/main.cjs
fi

echo ""
echo "[*] ForensiVault session terminated."
