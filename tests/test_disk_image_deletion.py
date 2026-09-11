import urllib.request
import json
import os
import sqlite3

BASE = "http://127.0.0.1:8765/api"

def post(endpoint, payload):
    req = urllib.request.Request(
        f"{BASE}{endpoint}",
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"}
    )
    try:
        with urllib.request.urlopen(req) as resp:
            return resp.status, json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read().decode("utf-8"))

def main():
    print("============================================================")
    print("   AUTOMATED DISK IMAGE REAL DELETION VERIFICATION SUITE    ")
    print("============================================================")

    # STEP 1: CREATE TEST DISK IMAGE
    print("\n[STEP 1] Generating standard test disk image (test-disk.img)...")
    st, res = post("/image/create-test-disk", {"output_path": r"D:\SIH\test_data\test-disk.img"})
    assert st == 200, f"Expected 200, got {st}"
    img_path = res["path"]
    sz = res["size_bytes"]
    fs = res["fs_type"]
    print(f" -> Test disk created at: {img_path} ({sz} bytes, FS: {fs})")
    print(" -> Initial files created:", res["files_created"])

    # STEP 2: INSPECT FILESYSTEM
    print("\n[STEP 2] Inspecting disk image filesystem...")
    st, ins = post("/image/inspect", {"image_path": img_path})
    assert st == 200
    assert ins["fs_type"] == "FAT32"
    assert ins["can_modify"] == True
    active_files = [f for f in ins["files"] if f["status"] == "ACTIVE"]
    print(f" -> Detected FS: {ins['fs_type']} (Can Modify: {ins['can_modify']})")
    print(f" -> Found {len(active_files)} active entries:")
    for f in active_files:
        print(f"    * {f['full_path']} ({f['size_bytes']} B, {f['file_type']})")

    assert any(f["full_path"] == "/TEST.TXT" for f in active_files)
    assert any(f["full_path"] == "/DOCUMENT.PDF" for f in active_files)
    assert any(f["full_path"] == "/PHOTOS/IMAGE.JPG" for f in active_files)
    assert any(f["full_path"] == "/SAMPLE/DATA.BIN" for f in active_files)

    # STEP 3: PERFORM NORMAL DELETE ON TEST.TXT
    print("\n[STEP 3] Performing NORMAL DELETE on /TEST.TXT inside test-disk.img...")
    st, del_norm = post("/image/delete-file", {
        "image_path": img_path,
        "file_path": "/TEST.TXT",
        "mode": "normal",
        "make_backup": True
    })
    assert st == 200, f"Expected 200, got {st}: {del_norm}"
    assert del_norm["success"] == True
    assert del_norm["verified_deleted"] == True
    assert del_norm["hash_changed"] == True
    print(f" -> Delete result: {del_norm['message']}")
    print(f" -> Pre-hash:  {del_norm['pre_hash'][:24]}...")
    print(f" -> Post-hash: {del_norm['post_hash'][:24]}...")
    print(f" -> Backup created: {del_norm.get('backup_path')}")

    # STEP 4: CLOSE AND REOPEN IMAGE TO VERIFY PERSISTENCE
    print("\n[STEP 4] Reopening disk image from scratch and rescanning directory...")
    st, ins_after1 = post("/image/inspect", {"image_path": img_path})
    assert st == 200
    active_after1 = [f["full_path"] for f in ins_after1["files"] if f["status"] == "ACTIVE"]
    deleted_after1 = [f["full_path"] for f in ins_after1["files"] if f["status"] == "DELETED"]
    print(f" -> Active files remaining: {active_after1}")
    print(f" -> Deleted files detected: {deleted_after1}")
    assert "/TEST.TXT" not in active_after1, "/TEST.TXT must no longer be active"
    assert "/DOCUMENT.PDF" in active_after1, "/DOCUMENT.PDF must remain unaffected"
    assert "/PHOTOS/IMAGE.JPG" in active_after1, "/PHOTOS/IMAGE.JPG must remain unaffected"
    assert "/SAMPLE/DATA.BIN" in active_after1, "/SAMPLE/DATA.BIN must remain unaffected"
    assert any("_EST.TXT" in p for p in deleted_after1), "Tombstone 0xE5 entry must be recorded"

    # STEP 5: PERFORM SECURE WIPE ON DOCUMENT.PDF
    print("\n[STEP 5] Performing SECURE WIPE on /DOCUMENT.PDF...")
    st, del_wipe = post("/image/delete-file", {
        "image_path": img_path,
        "file_path": "/DOCUMENT.PDF",
        "mode": "secure_wipe",
        "make_backup": False
    })
    assert st == 200
    assert del_wipe["success"] == True
    assert del_wipe["verified_deleted"] == True
    print(f" -> Wipe result: {del_wipe['message']}")
    print(f" -> Clusters freed: {del_wipe['clusters_freed']}")

    # STEP 6: REOPEN IMAGE AGAIN AND VERIFY
    print("\n[STEP 6] Reopening disk image after SECURE WIPE...")
    st, ins_after2 = post("/image/inspect", {"image_path": img_path})
    assert st == 200
    active_after2 = [f["full_path"] for f in ins_after2["files"] if f["status"] == "ACTIVE"]
    print(f" -> Active files remaining: {active_after2}")
    assert "/DOCUMENT.PDF" not in active_after2, "/DOCUMENT.PDF must no longer be active"
    assert "/PHOTOS/IMAGE.JPG" in active_after2, "/PHOTOS/IMAGE.JPG must remain unaffected"
    assert "/SAMPLE/DATA.BIN" in active_after2, "/SAMPLE/DATA.BIN must remain unaffected"

    # STEP 7: ERROR HANDLING TESTS
    print("\n[STEP 7] Testing error handling...")
    # 7A: Already deleted / not found
    st, err_nf = post("/image/delete-file", {"image_path": img_path, "file_path": "/NONEXISTENT.TXT"})
    print(f" -> Non-existent file error: HTTP {st}, error: {err_nf.get('error')}")
    assert st == 400

    # 7B: Read-only / Unsupported filesystem (exFAT)
    st, err_exfat = post("/image/delete-file", {"image_path": r"D:\SIH\test_data\exfat_evidence.img", "file_path": "/SOMEFILE.BIN"})
    print(f" -> Unsupported FS error: HTTP {st}, error: {err_exfat.get('error')}, msg: {err_exfat.get('message')}")
    assert st == 400
    assert err_exfat.get("error") == "UNSUPPORTED_FILESYSTEM"

    # 7C: Physical drive safety block
    st, err_phys = post("/image/delete-file", {"image_path": r"\\.\PhysicalDrive0", "file_path": "/SOMEFILE.BIN"})
    print(f" -> Physical drive safety error: HTTP {st}, error: {err_phys.get('error')}")
    assert st == 400 or st == 403

    # STEP 8: AUDIT LEDGER PERSISTENCE CHECK
    print("\n[STEP 8] Checking SQLite audit ledger...")
    conn = sqlite3.connect(r"D:\SIH\database\forensivault.db")
    c = conn.cursor()
    c.execute("SELECT id, event_type, action, timestamp, details FROM audit_ledger WHERE event_type = 'VIRTUAL_DISK_DELETION' ORDER BY id DESC LIMIT 5")
    rows = c.fetchall()
    conn.close()
    print(f" -> Found {len(rows)} audit records for VIRTUAL_DISK_DELETION:")
    for r in rows:
        det = json.loads(r[4])
        print(f"    * [{r[3]}] {r[2]} -> Image: {det.get('image_name')} | File: {det.get('file_path')} | Mode: {det.get('operation_type')}")
    assert len(rows) >= 2, "Audit records must be stored for deletion events"

    print("\n============================================================")
    print(" >>> ALL END-TO-END DELETION TESTS COMPLETED SUCCESSFULLY! <<<")
    print("============================================================")

if __name__ == "__main__":
    main()

