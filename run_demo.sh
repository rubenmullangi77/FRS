#!/usr/bin/env bash
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BUILD_DIR="${SCRIPT_DIR}/build_linux"

echo "======================================================================"
echo "   ForensiVault Safe Demonstration Suite (Smart India Hackathon)"
echo "======================================================================"

echo "[1/3] Generating synthetic multi-file forensic evidence image..."
python3 tools/generate_demo_evidence.py test_data/evidence_demo.img

echo ""
echo "[2/3] Building latest C++ forensic engine and demonstration runner..."
if [ ! -d "${BUILD_DIR}" ]; then
    bash "${SCRIPT_DIR}/build.sh"
else
    cmake --build "${BUILD_DIR}" --target forensic-demo forensivault_cli
fi

echo ""
echo "[3/3] Executing end-to-end 12-step recovery & certified sanitization demo..."
"${BUILD_DIR}/bin/forensic-demo" test_data/evidence_demo.img

echo ""
echo "Demonstration finished. View case reports at:"
echo "  test_data/demo_workspace/reports/"
