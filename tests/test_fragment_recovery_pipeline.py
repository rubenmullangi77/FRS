"""
Automated Test for Fragmented File Recovery Pipeline
Verifies:
1. Generation of controlled fragmented evidence image (test_data/fragmented_recovery_test.img)
2. Discovery of disjoint candidate fragments across sectors
3. Conservative boundary & structural compatibility evaluation
4. Bit-perfect reconstruction of disjoint JPEG stream matching reference SHA-256
5. Conservative uncertainty handling: orphaned fragments kept segregated with diagnostic explanations
6. Integration with FastAPI /api/reconstruct endpoint
"""

import os
import sys
import hashlib
from pathlib import Path
from fastapi.testclient import TestClient

# Setup paths
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from backend_fastapi.main import app
from tools.generate_fragmented_image import generate_fragmented_image

def test_fragment_recovery():
    client = TestClient(app)

    test_img_path = PROJECT_ROOT / "test_data" / "fragmented_recovery_test.img"
    print(f"=== 1. Provision Fragmented Evidence Image: {test_img_path} ===")
    generate_fragmented_image(str(test_img_path))
    assert test_img_path.is_file(), f"Image was not created: {test_img_path}"

    # Calculate ground-truth hash of the known 149-byte reference JPEG
    reference_jpeg = bytes([
        0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10, 0x4A, 0x46, 0x49, 0x46, 0x00, 0x01,
        0x01, 0x01, 0x00, 0x48, 0x00, 0x48, 0x00, 0x00, 0xFF, 0xDB, 0x00, 0x43,
        0x00, 0x08, 0x06, 0x06, 0x07, 0x06, 0x05, 0x08, 0x07, 0x07, 0x07, 0x09,
        0x09, 0x08, 0x0A, 0x0C, 0x14, 0x0D, 0x0C, 0x0B, 0x0B, 0x0C, 0x19, 0x12,
        0x13, 0x0F, 0x14, 0x1D, 0x1A, 0x1F, 0x1E, 0x1D, 0x1A, 0x1C, 0x1C, 0x20,
        0x24, 0x2E, 0x27, 0x20, 0x22, 0x2C, 0x23, 0x1C, 0x1C, 0x28, 0x37, 0x29,
        0x2C, 0x30, 0x31, 0x34, 0x34, 0x34, 0x1F, 0x27, 0x39, 0x3D, 0x38, 0x32,
        0x3C, 0x2E, 0x33, 0x34, 0x32, 0xFF, 0xC0, 0x00, 0x0B, 0x08, 0x00, 0x01,
        0x00, 0x01, 0x01, 0x01, 0x11, 0x00, 0xFF, 0xC4, 0x00, 0x1F, 0x00, 0x00,
        0x01, 0x05, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0A, 0x0B, 0xFF, 0xDA, 0x00, 0x08, 0x01, 0x01, 0x00, 0x00, 0x3F,
        0x00, 0xBF, 0x00, 0xFF, 0xD9
    ])
    expected_sha256 = hashlib.sha256(reference_jpeg).hexdigest()
    print(f"[OK] Reference ground-truth JPEG SHA-256: {expected_sha256}")

    print("=== 2. Call /api/reconstruct Endpoint ===")
    req_body = {
        "image_path": str(test_img_path),
        "file_type": "JPEG",
        "case_id": "CASE-RECONSTRUCT-001"
    }
    resp = client.post("/api/reconstruct", json=req_body)
    assert resp.status_code == 200, f"Reconstruction failed: {resp.text}"
    data = resp.json()
    assert data.get("success") is True

    discovered = data.get("fragments", [])
    reconstructions = data.get("reconstructions", [])
    reconstructed_count = data.get("reconstructed_count", 0)
    segregated_count = data.get("segregated_count", 0)

    print(f"[OK] Discovered {len(discovered)} fragments across image")
    print(f"[OK] Reconstructed count: {reconstructed_count}, Segregated count: {segregated_count}")

    assert len(discovered) >= 2, f"Expected at least 2 fragments, got {len(discovered)}"
    assert reconstructed_count >= 1, f"Expected at least 1 successful reconstruction, got {reconstructed_count}"
    assert segregated_count >= 1, f"Expected at least 1 segregated uncertain fragment, got {segregated_count}"

    # 3. Verify successful reconstruction details
    successful = [r for r in reconstructions if r.get("is_reconstructed")]
    assert len(successful) >= 1, "No reconstruction marked as successful"
    recon = successful[0]

    assert recon.get("sha256") == expected_sha256, (
        f"Reconstructed SHA-256 mismatch!\nExpected: {expected_sha256}\nGot:      {recon.get('sha256')}"
    )
    assert recon.get("total_size") == len(reference_jpeg)
    assert len(recon.get("fragment_offsets", [])) == 2
    assert recon.get("confidence_score") >= 90.0
    print(f"[OK] Reconstructed JPEG SHA-256 MATCHES GROUND TRUTH BIT-PERFECTLY: {recon.get('sha256')}")

    # 4. Verify conservative segregation of uncertain orphan fragments
    segregated = [r for r in reconstructions if r.get("is_partial")]
    assert len(segregated) >= 1, "No reconstruction marked as partial/segregated"
    orphan = segregated[0]
    reason = orphan.get("uncertainty_reason", "")
    assert len(reason) > 0, "Orphan fragment has no diagnostic uncertainty reason"
    print(f"[OK] Conservative segregation verified. Diagnostic Reason: '{reason}'")

    print("\n>>> ALL FRAGMENT RECOVERY PIPELINE TESTS PASSED (100% Verified) <<<")

if __name__ == "__main__":
    test_fragment_recovery()
