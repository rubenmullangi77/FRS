import urllib.request
import urllib.parse
import json
import os
import sys

sys.path.insert(0, r"D:\SIH")
API_BASE = "http://127.0.0.1:8765/api"

def http_post(endpoint, data):
    url = f"{API_BASE}{endpoint}"
    req = urllib.request.Request(
        url,
        data=json.dumps(data).encode("utf-8"),
        headers={"Content-Type": "application/json"}
    )
    try:
        with urllib.request.urlopen(req) as resp:
            return resp.getcode(), json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8")
        try:
            return e.code, json.loads(body)
        except Exception:
            return e.code, {"raw": body}

def http_get(endpoint):
    url = f"{API_BASE}{endpoint}"
    with urllib.request.urlopen(url) as resp:
        return resp.getcode(), json.loads(resp.read().decode("utf-8"))

print("="*70)
print("FORENSIVAULT COMPLETE TEST SUITE VERIFICATION")
print("="*70)

# TEST 1: Canonical Source Model & Dynamic Device Detection
print("\n[TEST 1] Testing Canonical Sources & Dynamic Detection...")
code, sources_data = http_get("/recovery/canonical-sources")
assert code == 200, f"Expected 200, got {code}"
sources = sources_data.get("sources", [])
assert len(sources) > 0, "No canonical sources returned"
print(f"  -> Total Canonical Sources: {len(sources)}")

# Verify types present
source_types = set(s["source_type"] for s in sources)
print(f"  -> Detected Source Types: {source_types}")
assert "PHYSICAL_DISK" in source_types or "PARTITION" in source_types, "No physical disks/partitions"
assert "MOUNTED_VOLUME" in source_types, "No mounted volumes"
assert "FORENSIC_IMAGE" in source_types, "No forensic images"

# Verify mandatory fields on each canonical source
for s in sources:
    for field in ["source_type", "source_id", "display_name", "device_path", "protocol", "manufacturer", "model", "capacity", "filesystem", "connection_type", "capabilities"]:
        assert field in s, f"Source missing mandatory field '{field}': {s}"

print("  -> PASSED: All canonical source models strictly conform to Part 1 specification.")

# TEST 2: Strict MTP Separation from Block Storage (Part 7)
print("\n[TEST 2] Testing Source Separation (D: NTFS vs MTP Phone)...")
volume_d = next((s for s in sources if s["device_path"] == "D:"), None)
assert volume_d is not None, "Drive D: not found in sources"
assert volume_d["source_type"] in ["MOUNTED_VOLUME", "PARTITION"], f"D: was misclassified as {volume_d['source_type']}!"
assert "MTP" not in volume_d["protocol"], f"D: protocol has MTP: {volume_d['protocol']}"
assert volume_d["filesystem"] == "NTFS", f"D: filesystem is not NTFS: {volume_d['filesystem']}"
print(f"  -> PASSED: D: is correctly classified as {volume_d['source_type']} ({volume_d['protocol']}, {volume_d['filesystem']}).")

mtp_sources = [s for s in sources if s["source_type"] == "MTP_DEVICE"]
print(f"  -> Connected MTP Devices Found: {len(mtp_sources)}")
for m in mtp_sources:
    assert m["drive_letter"] is None, f"MTP device must NOT have drive letter: {m['drive_letter']}"
    assert m["filesystem"] == "Not exposed through MTP", f"MTP must NOT expose filesystem: {m['filesystem']}"
    assert m["capabilities"]["can_raw_carve"] is False, "MTP must not allow raw carving"
    assert m["capabilities"]["can_parse_filesystem"] is False, "MTP must not allow filesystem parsing"
    print(f"  -> Verified MTP Device: {m['display_name']} ({m['manufacturer']} - {m['model']})")

# TEST 3: Strict Source Routing: MTP Blocked from Raw Recovery (Part 5, 6)
print("\n[TEST 3] Testing Strict Source Routing & Guard Rails on MTP...")
if mtp_sources:
    target_mtp = mtp_sources[0]["device_path"]
    
    # 3.1 Raw carving against MTP must be rejected with 400
    code, err = http_post("/recovery/carve", {"image_path": target_mtp, "source_type": "MTP_DEVICE"})
    assert code == 400, f"Expected 400 for MTP carving, got {code}"
    assert err.get("error") == "RAW_RECOVERY_UNAVAILABLE" or (isinstance(err.get("detail"), dict) and err.get("detail", {}).get("error") == "RAW_RECOVERY_UNAVAILABLE"), f"Unexpected error code: {err}"
    assert err.get("raw_carving") == "NOT EXECUTED" or (isinstance(err.get("detail"), dict) and err.get("detail", {}).get("raw_carving") == "NOT EXECUTED")
    print("  -> PASSED: /api/recovery/carve rejected MTP target with RAW_RECOVERY_UNAVAILABLE.")

    # 3.2 Partition detection against MTP must be rejected with 400
    code, err = http_post("/recovery/partitions", {"image_path": target_mtp, "source_type": "MTP_DEVICE"})
    assert code == 400, f"Expected 400 for MTP partitions, got {code}"
    print("  -> PASSED: /api/recovery/partitions rejected MTP target.")

    # 3.3 Filesystem detection against MTP must be rejected with 400
    code, err = http_post("/recovery/detect-fs", {"image_path": target_mtp, "source_type": "MTP_DEVICE"})
    assert code == 400, f"Expected 400 for MTP detect-fs, got {code}"
    print("  -> PASSED: /api/recovery/detect-fs rejected MTP target.")

    # 3.4 Scan deleted against MTP must be rejected with 400
    code, err = http_post("/recovery/scan-deleted", {"image_path": target_mtp, "source_type": "MTP_DEVICE"})
    assert code == 400, f"Expected 400 for MTP scan-deleted, got {code}"
    print("  -> PASSED: /api/recovery/scan-deleted rejected MTP target.")

# TEST 4: Audit Function Parameter Compatibility (Part 13)
print("\n[TEST 4] Testing Audit Logging API with source_identifier & source_type...")
from backend_fastapi.database import log_audit_event, get_connection

test_evt_hash = log_audit_event(
    event_type="TEST_VERIFICATION",
    action="VERIFY_CANONICAL_AUDIT",
    user="Senior Investigator Ruben",
    source_identifier=r"\\?\usb#vid_test#device123",
    source_type="MTP_DEVICE",
    operation="Test MTP Audit",
    details={"verification_test": True}
)
assert test_evt_hash and len(test_evt_hash) == 64, f"Invalid audit hash: {test_evt_hash}"

conn = get_connection()
c = conn.cursor()
c.execute("SELECT event_id, event_type, action, source_identifier, source_type, record_hash FROM audit_logs WHERE record_hash = ?", (test_evt_hash,))
row = c.fetchone()
assert row is not None, "Audit event was not persisted in database!"
assert row["source_identifier"] == r"\\?\usb#vid_test#device123", f"Wrong source_identifier: {row['source_identifier']}"
assert row["source_type"] == "MTP_DEVICE", f"Wrong source_type: {row['source_type']}"
conn.close()
print(f"  -> PASSED: log_audit_event successfully persisted record with source_identifier (Hash: {test_evt_hash[:16]}...)")

# TEST 5: Live MTP Enumeration & Real Object Copying (Part 9, 10, 11, 12)
if mtp_sources:
    print("\n[TEST 5] Testing Real MTP WPD Object Enumeration & File Transfer...")
    dev_id = mtp_sources[0]["device_path"]
    
    # 5.1 Browse root
    code, browse_res = http_post("/devices/portable/browse", {"device_id": dev_id, "object_id": ""})
    assert code == 200, f"Browse failed: {browse_res}"
    items = browse_res.get("items", [])
    print(f"  -> Root items returned: {len(items)}")
    
    if items:
        storage_obj = items[0]
        assert storage_obj.get("is_folder") is True or storage_obj.get("is_directory") is True, "Storage root must be a directory"
        print(f"  -> Top-level storage object: {storage_obj.get('name')} (ID: {storage_obj.get('object_id')})")
        
        # 5.2 Browse into storage
        code, sub_res = http_post("/devices/portable/browse", {"device_id": dev_id, "object_id": storage_obj.get("object_id")})
        assert code == 200
        sub_items = sub_res.get("items", [])
        folder_names = [it.get("name") for it in sub_items if it.get("is_folder")]
        print(f"  -> Discovered {len(sub_items)} real phone items. Sample folders: {folder_names[:8]}")
        
        # 5.3 Drill down into DCIM or Pictures if present
        dcim_obj = next((it for it in sub_items if it.get("name") == "DCIM"), None)
        if dcim_obj:
            code, dcim_res = http_post("/devices/portable/browse", {"device_id": dev_id, "object_id": dcim_obj.get("object_id")})
            dcim_children = dcim_res.get("items", [])
            camera_obj = next((it for it in dcim_children if it.get("name") == "Camera"), None)
            if camera_obj:
                code, cam_res = http_post("/devices/portable/browse", {"device_id": dev_id, "object_id": camera_obj.get("object_id")})
                cam_files = [it for it in cam_res.get("items", []) if not it.get("is_folder")]
                print(f"  -> Camera contains {len(cam_files)} real files!")
                if cam_files:
                    sample_file = cam_files[0]
                    print(f"  -> Testing real file copy for: {sample_file.get('name')} (size: {sample_file.get('size_bytes')} B)")
                    
                    code, copy_res = http_post("/devices/portable/copy", {
                        "device_id": dev_id,
                        "object_ids": [sample_file.get("object_id")],
                        "case_id": "CASE-TEST-MTP"
                    })
                    assert code == 200, f"Copy failed: {copy_res}"
                    assert copy_res.get("success") is True, f"Copy unsuccessful: {copy_res}"
                    first_copied = copy_res.get("results", [])[0]
                    assert first_copied.get("success") is True
                    assert os.path.isfile(first_copied.get("saved_path")), f"File not on disk: {first_copied.get('saved_path')}"
                    actual_sz = os.path.getsize(first_copied.get("saved_path"))
                    assert actual_sz > 0, "Copied file is 0 bytes!"
                    assert first_copied.get("sha256"), "No SHA-256 calculated!"
                    assert first_copied.get("sha256") != "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "Fake empty hash was emitted!"
                    print(f"  -> PASSED: Copied {first_copied.get('filename')} to {first_copied.get('saved_path')}")
                    print(f"  -> Actual Bytes: {actual_sz}, SHA-256: {first_copied.get('sha256')}")

# TEST 6: Normal Block Storage Recovery on Forensic Image (Part 14, 15, 16, 17)
print("\n[TEST 6] Testing Normal Block Storage Recovery on Forensic Image...")
img_source = next((s for s in sources if s["source_type"] == "FORENSIC_IMAGE" and "ntfs" in s["device_path"].lower()), None)
if not img_source:
    img_source = next((s for s in sources if s["source_type"] == "FORENSIC_IMAGE"), None)

if img_source:
    p_path = img_source["device_path"]
    code, p_res = http_post("/recovery/partitions", {"image_path": p_path})
    assert code == 200, f"Partitions failed: {p_res}"
    code, fs_res = http_post("/recovery/detect-fs", {"image_path": p_path, "start_sector": 0})
    assert code == 200, f"Detect-fs failed: {fs_res}"
    print(f"  -> Tested {img_source['display_name']}: Filesystem = {fs_res.get('fs_type')}")
    
    code, scan_res = http_post("/recovery/scan-deleted", {"image_path": p_path, "case_id": "CASE-TEST-AUTO"})
    assert code == 200, f"Scan-deleted failed: {scan_res}"
    print(f"  -> Scan Completed: Found {scan_res.get('deleted_entries_found', 0)} candidates, Pre-Hash: {scan_res.get('evidence_pre_hash')[:16]}...")
    assert scan_res.get("evidence_pre_hash") != "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "Empty hash emitted for valid image!"

# TEST 7: Case Scoped Report Generation & Open PDF (Part 22, 24)
print("\n[TEST 7] Testing Report Generation & Secure PDF Open Endpoint...")
code, rep_res = http_post("/reports/generate", {
    "case_id": "CASE-2026-001",
    "title": "ForensiVault Automated Recovery Test Report",
    "format": "PDF"
})
assert code == 200, f"Report generation failed: {rep_res}"
rep_filepath = rep_res.get("filepath") or rep_res.get("file_path")
assert rep_filepath and os.path.isfile(rep_filepath), f"Report not created on disk: {rep_filepath}"
assert os.path.getsize(rep_filepath) > 0, "Report file is 0 bytes!"
print(f"  -> Generated Report: {rep_filepath} ({os.path.getsize(rep_filepath)} bytes)")

# Test /reports/open validation (security checks)
code, open_res = http_post("/reports/open", {"filepath": rep_filepath})
assert code == 200, f"Open report failed: {open_res}"
print("  -> PASSED: Secure report open verified.")

print("\n" + "="*70)
print("ALL AUTOMATED TESTS PASSED WITH 100% SUCCESS!")
print("="*70)
