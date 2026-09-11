#!/usr/bin/env bash
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BUILD_DIR="${SCRIPT_DIR}/build_linux"

echo "======================================================================"
echo "          FORENSIVAULT FORENSIC INVESTIGATION PLATFORM"
echo "               Linux C++ Build Automation"
echo "======================================================================"
echo ""

if [ ! -d "${BUILD_DIR}" ]; then
    echo "[*] Creating separate build directory: ${BUILD_DIR}"
    mkdir -p "${BUILD_DIR}"
fi

echo "[*] Configuring CMake in ${BUILD_DIR}..."
cmake -B "${BUILD_DIR}" -G "Unix Makefiles" -DCMAKE_BUILD_TYPE=Release "${SCRIPT_DIR}"

NPROC=$(nproc 2>/dev/null || echo 4)
echo "[*] Building all ForensiVault C++ targets with ${NPROC} parallel jobs..."
cmake --build "${BUILD_DIR}" -j"${NPROC}"

echo ""
echo "[+] Build completed successfully!"
echo "    Binaries located at: ${BUILD_DIR}/bin/"
echo "    - forensivault_cli"
echo "    - forensivault_server"
echo "    - forensivault_tests"
echo "    - forensic-inspect"
echo "    - forensic-demo"
echo "    - libforensivault_native.so"
echo "======================================================================"
