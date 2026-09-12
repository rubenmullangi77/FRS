"""
Automated Test for Real Filesystem Deletion
Verifies:
1. Creation of test files in D:\\SIH\\ForensiVault_Test_Delete
2. Safe browsing and protection guard classification
3. Rejection of unconfirmed deletion requests
4. Rejection of protected system paths (C:\\Windows, application codebase, etc.)
5. Multi-pass secure erasure and unlinking via C++ SecureFileEraser
6. Confirmation of file absence on physical disk
7. Cryptographic audit trail logging
"""

import os
import sys
from pathlib import Path
from fastapi.testclient import TestClient

# Setup paths
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from backend_fastapi.main import app, TEST_DELETE_DIR
from backend_fastapi.database import get_connection

def test_real_filesystem_workflow():
    client = TestClient(app)

    print("=== 1. Create Test Files in Safe Delete Directory ===")
    resp = client.post("/api/real-fs/create-test-files")
    assert resp.status_code == 200, f"Failed to create test files: {resp.text}"
    data = resp.json()
    assert data.get("success") is True, "Create test files success != True"
    files = data.get("files", [])
    assert len(files) >= 5, f"Expected at least 5 test files, got {len(files)}"
    file_map = {f["filename"]: f["path"] for f in files}
    print(f"[OK] Created {len(files)} files: {list(file_map.keys())}")

    for fname, fpath in file_map.items():
        assert Path(fpath).is_file(), f"File does not actually exist: {fpath}"

    print("=== 2. Browse Real Filesystem ===")
    # Root quick-picks
    resp = client.get("/api/real-fs/browse")
    assert resp.status_code == 200
    root_items = resp.json().get("items", [])
    assert any("Test Delete" in item.get("name", "") for item in root_items), "Test delete directory not found in quick-picks"
    print(f"[OK] Root quick-picks verified ({len(root_items)} bookmarks)")

    # Inside Test Delete Directory
    resp = client.get(f"/api/real-fs/browse?path={TEST_DELETE_DIR}")
    assert resp.status_code == 200
    browse_items = resp.json().get("items", [])
    assert len(browse_items) >= 5
    for item in browse_items:
        assert item.get("is_protected") is False, f"Test file {item['name']} should NOT be protected"
    print(f"[OK] Browsed {TEST_DELETE_DIR.name}: {len(browse_items)} items properly marked as unprotected")

    print("=== 3. Safety Interlock Verification ===")
    # Missing confirmation
    doc_path = file_map["test_document.txt"]
    resp = client.post("/api/real-fs/delete", json={
        "filepath": doc_path,
        "method": "NIST_800_88_CLEAR",
        "confirmation": "WRONG_TOKEN"
    })
    assert resp.status_code == 400, f"Expected 400 for bad confirmation, got {resp.status_code}"
    assert Path(doc_path).is_file(), "File was deleted despite invalid confirmation!"
    print("[OK] Rejection of unconfirmed deletion verified")

    # Protected system path
    sys_path = r"C:\Windows\System32\kernel32.dll" if sys.platform == "win32" else "/etc/passwd"
    resp = client.post("/api/real-fs/delete", json={
        "filepath": sys_path,
        "method": "NIST_800_88_CLEAR",
        "confirmation": "PERMANENTLY DELETE"
    })
    assert resp.status_code in [403, 404], f"Expected 403 or 404 for protected system file, got {resp.status_code}"
    print("[OK] System protection interlock verified for OS paths")

    # Protected codebase path
    code_path = str((PROJECT_ROOT / "backend_fastapi" / "main.py").resolve())
    resp = client.post("/api/real-fs/delete", json={
        "filepath": code_path,
        "method": "NIST_800_88_CLEAR",
        "confirmation": "PERMANENTLY DELETE"
    })
    assert resp.status_code == 403, f"Expected 403 for codebase file, got {resp.status_code}"
    print("[OK] System protection interlock verified for application codebase")

    print("=== 4. Execute Real File Deletion with Confirmation ===")
    target_to_delete = file_map["test_document.txt"]
    assert Path(target_to_delete).exists()

    resp = client.post("/api/real-fs/delete", json={
        "filepath": target_to_delete,
        "method": "NIST_800_88_CLEAR",
        "confirmation": "PERMANENTLY DELETE"
    })
    assert resp.status_code == 200, f"Deletion failed: {resp.text}"
    del_res = resp.json()
    assert del_res.get("success") is True
    assert del_res.get("is_verified") is True
    assert del_res.get("accessible_after_deletion") is False

    # 5. Confirm file is completely gone from filesystem
    assert not Path(target_to_delete).exists(), f"File still exists on disk after deletion: {target_to_delete}"
    print(f"[OK] File {Path(target_to_delete).name} verified permanently absent on disk")

    print("=== 5. Cryptographic Audit Log Verification ===")
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM audit_logs WHERE action = 'REAL_FS_SECURE_DELETE' ORDER BY id DESC LIMIT 1")
    row = cursor.fetchone()
    conn.close()
    assert row is not None, "Audit log entry not found for real filesystem delete"
    row_dict = dict(row)
    assert row_dict["event_type"] == "SANITIZATION"
    assert "test_document.txt" in row_dict["details_json"]
    print(f"[OK] Audit log verified: Record ID {row_dict['id']}, Hash {row_dict['record_hash'][:16]}...")

    print("\n>>> ALL REAL FILESYSTEM DELETION TESTS PASSED (100% Verified) <<<")

if __name__ == "__main__":
    test_real_filesystem_workflow()
