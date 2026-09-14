import sys
import json
import urllib.request
import urllib.error
from pathlib import Path

BASE_URL = "http://127.0.0.1:8765"
MTP_DEVICE_PATH = r"\\?\usb#vid_2d95&pid_6002#1363314327000uf#{6ac27878-a6fa-4155-ba85-f98f491d4f33}"
FAT32_IMAGE_PATH = r"D:\SIH\test_data\fat32_evidence.img"

def post_json(endpoint: str, payload: dict):
    req = urllib.request.Request(
        f"{BASE_URL}{endpoint}",
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"}
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return resp.status, json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8")
        try:
            return e.code, json.loads(body)
        except Exception:
            return e.code, {"raw": body}

def test_mtp_rejection():
    print("\n========================================================")
    print("TEST 1: MTP DEVICE REJECTION ON RAW SECTOR / CARVING APIS")
    print("========================================================")
    
    endpoints = [
        ("/api/recovery/scan-unallocated", {"image_path": MTP_DEVICE_PATH, "case_id": "CASE-2026-001"}),
        ("/api/carve/start", {"image_path": MTP_DEVICE_PATH, "case_id": "CASE-2026-001"}),
        ("/api/recovery/carve", {"image_path": MTP_DEVICE_PATH, "case_id": "CASE-2026-001"}),
        ("/api/recovery/partitions", {"image_path": MTP_DEVICE_PATH}),
        ("/api/recovery/detect-fs", {"image_path": MTP_DEVICE_PATH, "start_sector": 0}),
        ("/api/recovery/scan-deleted", {"image_path": MTP_DEVICE_PATH, "start_sector": 0, "case_id": "CASE-2026-001"}),
        ("/api/recovery/extract", {"image_path": MTP_DEVICE_PATH, "start_sector": 0, "case_id": "CASE-2026-001", "file_ids": [1]})
    ]

    for ep, payload in endpoints:
        status, data = post_json(ep, payload)
        print(f"Testing {ep} with MTP path -> HTTP {status}")
        assert status == 400, f"Expected HTTP 400 for {ep}, got {status}: {data}"
        err = data.get("error") or (data.get("detail", {}).get("error") if isinstance(data.get("detail"), dict) else None)
        assert err == "RAW_RECOVERY_UNAVAILABLE", f"Expected error RAW_RECOVERY_UNAVAILABLE, got {err} in {data}"
        msg = data.get("message") or (data.get("detail", {}).get("message") if isinstance(data.get("detail"), dict) else data.get("detail"))
        assert "Raw sector recovery is not available through MTP" in str(msg), f"Unexpected message: {msg}"
        print(f"  [PASS] Correctly rejected: error={err}")

def test_forensic_image_pipeline():
    print("\n========================================================")
    print("TEST 2: FORENSIC DISK IMAGE PIPELINE REMAINS FULLY FUNCTIONAL")
    print("========================================================")
    assert Path(FAT32_IMAGE_PATH).is_file(), f"Test image missing: {FAT32_IMAGE_PATH}"

    # 1. Partitions
    status, p_data = post_json("/api/recovery/partitions", {"image_path": FAT32_IMAGE_PATH})
    print(f"Partitions on {Path(FAT32_IMAGE_PATH).name} -> HTTP {status}")
    assert status == 200, f"Partition detection failed: {p_data}"
    print(f"  [PASS] Table Type: {p_data.get('table_type')}, Partitions: {len(p_data.get('partitions', []))}")

    # 2. Filesystem detect
    status, fs_data = post_json("/api/recovery/detect-fs", {"image_path": FAT32_IMAGE_PATH, "start_sector": 0})
    print(f"Detect FS -> HTTP {status}")
    assert status == 200, f"FS detect failed: {fs_data}"
    assert fs_data.get("is_detected") is True, f"FS not detected: {fs_data}"
    print(f"  [PASS] Filesystem detected: {fs_data.get('fs_type')}")

    # 3. Scan deleted files
    status, scan_data = post_json("/api/recovery/scan-deleted", {
        "image_path": FAT32_IMAGE_PATH,
        "start_sector": 0,
        "case_id": "CASE-2026-TEST"
    })
    print(f"Scan deleted -> HTTP {status}")
    assert status == 200, f"Scan deleted failed: {scan_data}"
    files = scan_data.get("files", [])
    print(f"  [PASS] Deleted entries found: {len(files)}")

    # 4. Extract files and generate Recovery PDF
    if files:
        rec_id = files[0]["id"]
        status, ext_data = post_json("/api/recovery/extract", {
            "image_path": FAT32_IMAGE_PATH,
            "start_sector": 0,
            "case_id": "CASE-2026-TEST",
            "file_ids": [rec_id]
        })
        print(f"Extract files -> HTTP {status}")
        assert status == 200, f"Extract failed: {ext_data}"
        assert ext_data.get("report_generated") is True, "Expected recovery report to be generated"
        pdf_path = ext_data.get("recovery_report", {}).get("file_path")
        assert pdf_path and Path(pdf_path).is_file(), f"Generated PDF not found: {pdf_path}"
        print(f"  [PASS] Recovery PDF successfully generated at: {pdf_path}")
        print(f"  [PASS] Pre-hash: {ext_data.get('evidence_pre_hash')[:16]}... Post-hash: {ext_data.get('evidence_post_hash')[:16]}...")

    # 5. Raw carving on image
    status, carve_data = post_json("/api/recovery/scan-unallocated", {
        "image_path": FAT32_IMAGE_PATH,
        "case_id": "CASE-2026-TEST"
    })
    print(f"Carve unallocated on image -> HTTP {status}")
    assert status == 200, f"Carve unallocated failed: {carve_data}"
    print(f"  [PASS] Carving discovered files: {len(carve_data.get('files', []))}")

def test_mtp_copy_destination():
    print("\n========================================================")
    print("TEST 3: MTP COPY DESTINATION FORMAT")
    print("========================================================")
    # Test copy portable files endpoint structure
    status, data = post_json("/api/devices/portable/copy", {
        "device_id": "test_device_id",
        "object_ids": [],
        "case_id": "CASE-2026-001"
    })
    print(f"MTP Copy route -> HTTP {status}")
    assert status == 200, f"MTP copy failed: {data}"
    dest = data.get("destination_directory", "")
    print(f"  Destination directory: {dest}")
    assert r"ForensiVault_Evidence\CASE-2026-001\MTP_Acquisition" in dest or r"ForensiVault_Evidence/CASE-2026-001/MTP_Acquisition" in dest, f"Unexpected destination: {dest}"
    print("  [PASS] Correct ForensiVault_Evidence/<CASE>/MTP_Acquisition destination path verified!")

def test_audit_log_safety():
    print("\n========================================================")
    print("TEST 4: AUDIT LOG SAFETY (NO RAW CARVING ON MTP)")
    print("========================================================")
    # Log MTP inspection
    status, _ = post_json("/api/recovery/audit-mtp-inspection", {
        "device_id": MTP_DEVICE_PATH,
        "device_name": "vivo iQOO 7",
        "manufacturer": "vivo",
        "case_id": "CASE-2026-001",
        "examiner_name": "Senior Investigator Ruben"
    })
    assert status == 200

    # Fetch audit logs
    req = urllib.request.Request(f"{BASE_URL}/api/audit/logs")
    with urllib.request.urlopen(req, timeout=5) as resp:
        audit_data = json.loads(resp.read().decode())
    
    entries = audit_data.get("entries", [])
    print(f"Total audit log entries: {len(entries)}")
    for e in entries:
        raw_str = json.dumps(e)
        if "MTP" in raw_str:
            assert "Initiating Raw File Carving" not in raw_str, f"Found forbidden carving string in MTP log: {raw_str}"
    print("  [PASS] Verified: Audit log contains zero forbidden raw carving events for MTP!")

def test_write_blocker_purged():
    print("\n========================================================")
    print("TEST 5: MISLEADING WRITE-BLOCKER TERMINOLOGY PURGED")
    print("========================================================")
    files_to_check = [
        r"D:\SIH\backend_fastapi\main.py",
        r"D:\SIH\backend_fastapi\recovery_pdf_generator.py",
        r"D:\SIH\frontend\src\pages\RecoveryPage.tsx"
    ]
    for fp in files_to_check:
        with open(fp, "r", encoding="utf-8") as f:
            text = f.read()
            assert "Hardware Write-Blocker Emulation" not in text, f"Misleading string still present in {fp}"
            assert "hardware write-blocker emulation" not in text, f"Misleading string still present in {fp}"
            assert "Hardware write-blocker emulation" not in text, f"Misleading string still present in {fp}"
            print(f"  [PASS] Verified clean: {Path(fp).name}")

if __name__ == "__main__":
    try:
        test_mtp_rejection()
        test_forensic_image_pipeline()
        test_mtp_copy_destination()
        test_audit_log_safety()
        test_write_blocker_purged()
        print("\n========================================================")
        print("ALL 5 COMPREHENSIVE FORENSIC VERIFICATION TESTS PASSED!")
        print("========================================================")
    except Exception as ex:
        print(f"\n[FAIL] Test assertion failed: {ex}")
        sys.exit(1)
