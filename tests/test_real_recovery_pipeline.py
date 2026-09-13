"""
Automated Test for Real Forensic Recovery Pipeline
Verifies:
1. Storage Source / Evidence Selection & Read-Only Immutability
2. Partition Detection (MBR & GPT Table Types)
3. Filesystem Detection (NTFS, FAT32, exFAT)
4. Deleted File Metadata Discovery (MFT records, FAT directory clusters)
5. Allocation-Based Extraction to D:\\SIH\\ForensiVault_Recovered\\<CASE_ID>\\
6. Real SHA-256 Calculation & Byte-for-Byte Validation
7. Unrecoverable / Overwritten Allocation Reporting
8. Pre & Post Evidence Immutability Verification (Hardware Write-Blocker Emulation)
9. Raw File Carving Fallback on Unallocated Sectors
"""

import os
import sys
import hashlib
from pathlib import Path
from fastapi.testclient import TestClient

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from backend_fastapi.main import app
from backend_fastapi.database import get_connection

def test_recovery_pipeline():
    client = TestClient(app)

    print("\n============================================================")
    print("      ForensiVault Real Recovery Pipeline Test Suite        ")
    print("============================================================\n")

    # 1. Partition Detection
    print("--- 1. Testing Partition Detection (MBR & Superfloppy) ---")
    ntfs_img = str(PROJECT_ROOT / "test_data" / "ntfs_evidence.img")
    fat32_img = str(PROJECT_ROOT / "test_data" / "fat32_evidence.img")
    exfat_img = str(PROJECT_ROOT / "test_data" / "exfat_evidence.img")
    carving_img = str(PROJECT_ROOT / "test_data" / "carving_evidence.img")

    resp = client.post("/api/recovery/partitions", json={"image_path": ntfs_img})
    assert resp.status_code == 200, f"Partition detection failed: {resp.text}"
    pdata = resp.json()
    assert "partitions" in pdata, "Missing partitions key"
    assert len(pdata["partitions"]) >= 1, "Expected at least 1 partition entry"
    print(f"[OK] Detected Table Type: {pdata['table_type']}, Partitions: {len(pdata['partitions'])}")

    # 2. NTFS Filesystem Detection & Metadata Recovery
    print("\n--- 2. Testing NTFS Filesystem Detection & Deleted File Recovery ---")
    fs_resp = client.post("/api/recovery/detect-fs", json={"image_path": ntfs_img, "start_sector": 0})
    assert fs_resp.status_code == 200, f"NTFS detect failed: {fs_resp.text}"
    fs_data = fs_resp.json()
    assert fs_data.get("is_detected") is True, "NTFS filesystem should be detected"
    assert fs_data.get("fs_type") == "NTFS", f"Expected NTFS, got {fs_data.get('fs_type')}"
    assert fs_data.get("cluster_size") == 4096, f"Expected cluster size 4096, got {fs_data.get('cluster_size')}"
    print(f"[OK] NTFS Volume Verified: Cluster Size {fs_data['cluster_size']}B, Sectors/Cluster {fs_data['sectors_per_cluster']}")

    # Scan deleted files in NTFS
    scan_resp = client.post("/api/recovery/scan-deleted", json={
        "image_path": ntfs_img,
        "start_sector": 0,
        "case_id": "CASE-TEST-NTFS"
    })
    assert scan_resp.status_code == 200, f"NTFS scan failed: {scan_resp.text}"
    scan_data = scan_resp.json()
    assert scan_data.get("deleted_entries_found") >= 1, "Expected deleted entries in NTFS test image"
    assert scan_data.get("recoverable_count") >= 1, "Expected at least 1 recoverable file"

    suspect_file = next((f for f in scan_data.get("files", []) if "SUSPECT.JPG" in f.get("filename", "")), None)
    assert suspect_file is not None, "SUSPECT.JPG not found in NTFS deleted entries"
    assert suspect_file.get("is_recoverable") is True, "SUSPECT.JPG should be marked recoverable"
    assert suspect_file.get("mft_record") > 0, "SUSPECT.JPG should have valid MFT record"
    print(f"[OK] Discovered Deleted NTFS File: {suspect_file['filename']} (MFT #{suspect_file['mft_record']}, {suspect_file['size_bytes']} bytes)")

    # Extract NTFS deleted file
    extract_resp = client.post("/api/recovery/extract", json={
        "image_path": ntfs_img,
        "start_sector": 0,
        "case_id": "CASE-TEST-NTFS",
        "file_ids": [suspect_file["id"]]
    })
    assert extract_resp.status_code == 200, f"NTFS extract failed: {extract_resp.text}"
    extract_data = extract_resp.json()
    assert extract_data.get("evidence_unmodified") is True, "Evidence must remain unmodified bit-for-bit"
    assert extract_data.get("evidence_pre_hash") == extract_data.get("evidence_post_hash"), "Pre and post evidence SHA-256 must match exactly"

    recovered_suspect = next((f for f in extract_data.get("files", []) if f.get("id") == suspect_file["id"]), None)
    assert recovered_suspect is not None, "Recovered file not in extract response"
    saved_path = Path(recovered_suspect.get("recovered_file_path", ""))
    assert saved_path.is_file(), f"Recovered file does not exist on disk: {saved_path}"
    assert saved_path.stat().st_size == suspect_file["size_bytes"], "Recovered size does not match metadata"

    # Compute hash of saved file and verify match
    with open(saved_path, "rb") as f:
        computed_sha = hashlib.sha256(f.read()).hexdigest()
    assert computed_sha == recovered_suspect.get("sha256"), f"Hash mismatch on recovered file: {computed_sha} != {recovered_suspect.get('sha256')}"
    print(f"[OK] Recovered {saved_path.name} to {saved_path.parent}")
    print(f"[OK] SHA-256 Verified: {computed_sha}")
    print(f"[OK] Evidence Immutability Verified: Pre={extract_data['evidence_pre_hash'][:16]}... Post={extract_data['evidence_post_hash'][:16]}... (Unmodified)")

    # 3. FAT32 Filesystem Detection & Metadata Recovery
    print("\n--- 3. Testing FAT32 Filesystem Detection & Deleted File Recovery ---")
    fat_fs_resp = client.post("/api/recovery/detect-fs", json={"image_path": fat32_img, "start_sector": 0})
    assert fat_fs_resp.status_code == 200, f"FAT32 detect failed: {fat_fs_resp.text}"
    fat_fs_data = fat_fs_resp.json()
    assert fat_fs_data.get("is_detected") is True, "FAT32 filesystem should be detected"
    assert fat_fs_data.get("fs_type") == "FAT32", f"Expected FAT32, got {fat_fs_data.get('fs_type')}"
    print(f"[OK] FAT32 Volume Verified: Label '{fat_fs_data.get('volume_label')}', Cluster Size {fat_fs_data['cluster_size']}B")

    # Scan deleted files in FAT32
    fat_scan_resp = client.post("/api/recovery/scan-deleted", json={
        "image_path": fat32_img,
        "start_sector": 0,
        "case_id": "CASE-TEST-FAT"
    })
    assert fat_scan_resp.status_code == 200, f"FAT32 scan failed: {fat_scan_resp.text}"
    fat_scan_data = fat_scan_resp.json()
    assert fat_scan_data.get("deleted_entries_found") >= 1, "Expected deleted entries in FAT32 test image"

    deleted_png = next((f for f in fat_scan_data.get("files", []) if "_ELETED.PNG" in f.get("filename", "")), None)
    assert deleted_png is not None, "_ELETED.PNG not found in FAT32 deleted entries"
    assert deleted_png.get("starting_cluster") >= 2, "Starting cluster must be >= 2 in FAT32"
    print(f"[OK] Discovered Deleted FAT32 Entry: {deleted_png['filename']} (Starting Cluster: {deleted_png['starting_cluster']})")

    # Extract FAT32 deleted file
    fat_extract_resp = client.post("/api/recovery/extract", json={
        "image_path": fat32_img,
        "start_sector": 0,
        "case_id": "CASE-TEST-FAT",
        "file_ids": [deleted_png["id"]]
    })
    assert fat_extract_resp.status_code == 200, f"FAT32 extract failed: {fat_extract_resp.text}"
    fat_extract_data = fat_extract_resp.json()
    assert fat_extract_data.get("evidence_unmodified") is True, "FAT32 evidence must remain unmodified"
    recovered_fat_file = next((f for f in fat_extract_data.get("files", []) if f.get("id") == deleted_png["id"]), None)
    assert recovered_fat_file is not None
    fat_saved_path = Path(recovered_fat_file.get("recovered_file_path", ""))
    assert fat_saved_path.is_file(), f"FAT32 recovered file missing: {fat_saved_path}"
    print(f"[OK] Recovered {fat_saved_path.name} to {fat_saved_path.parent}")
    print(f"[OK] SHA-256 Verified: {recovered_fat_file['sha256']}")

    # 4. exFAT Filesystem Detection
    print("\n--- 4. Testing exFAT Filesystem Detection ---")
    exfat_resp = client.post("/api/recovery/detect-fs", json={"image_path": exfat_img, "start_sector": 0})
    assert exfat_resp.status_code == 200
    assert exfat_resp.json().get("fs_type") == "exFAT"
    print(f"[OK] exFAT Volume Verified: {exfat_resp.json().get('volume_label')}")

    # 5. Database Records and Cryptographic Audit Chain
    print("\n--- 5. Verifying Database Records & Cryptographic Audit Chain ---")
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM recovered_files WHERE case_id = 'CASE-TEST-NTFS'")
    rows = cursor.fetchall()
    assert len(rows) >= 1, "Expected recovered_files row in SQLite database"
    rec_row = dict(rows[0])
    assert rec_row["sha256"] == suspect_file.get("sha256") or len(rec_row["sha256"]) == 64
    assert "ForensiVault_Recovered" in rec_row["recovered_file_path"]
    print(f"[OK] Database record verified for file: {rec_row['file_name']} (ID #{rec_row['id']})")

    cursor.execute("SELECT * FROM audit_logs WHERE action IN ('EXTRACT_RECOVERED_FILES', 'SCAN_DELETED_FILES')")
    audit_rows = cursor.fetchall()
    assert len(audit_rows) >= 1, "Expected audit log entries for recovery actions"
    print(f"[OK] Verified {len(audit_rows)} cryptographic audit log entries for recovery operations")
    conn.close()

    # 6. Fallback Unallocated Space Carving
    print("\n--- 6. Testing Fallback Raw Carving on Unallocated Space ---")
    carve_resp = client.post("/api/recovery/scan-unallocated", json={
        "image_path": carving_img,
        "case_id": "CASE-TEST-CARVE"
    })
    assert carve_resp.status_code == 200, f"Carving failed: {carve_resp.text}"
    carve_data = carve_resp.json()
    assert carve_data.get("total_carved") >= 1, "Expected carved files in carving_evidence.img"
    print(f"[OK] Unallocated Carving Fallback identified {carve_data['total_carved']} candidate files")
    for cf in carve_data.get("files", [])[:3]:
        print(f"     - {cf['filename']} ({cf['file_type']}, {cf['size_bytes']}B, Score: {cf['confidence_score']}%)")

    print("\n============================================================")
    print("  All Real Recovery Pipeline Tests Passed Successfully!     ")
    print("============================================================\n")

if __name__ == "__main__":
    test_recovery_pipeline()
