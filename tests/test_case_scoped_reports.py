"""
Automated Test for Strict Case-Scoped Forensic PDF Reports
Verifies:
1. Rejection of report generation with HTTP 400 when case_id is missing/empty.
2. Complete data isolation between CASE-001 and CASE-002.
3. Proper handling of zero-artifact cases ("No recovered files were recorded for this case.").
4. Correct filename format: ForensiVault_<CASE_ID>_Forensic_Report_<REPORT_ID>.pdf.
5. Download and Open endpoints with real files.
"""

import os
import sys
import re
from pathlib import Path
from datetime import datetime

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from fastapi.testclient import TestClient
from backend_fastapi.main import app, REPORTS_DIR
from backend_fastapi.database import get_connection, init_database

def setup_test_fixtures():
    init_database()
    conn = get_connection()
    cursor = conn.cursor()

    now = datetime.now().isoformat()

    # Provision Test Cases
    cursor.execute("DELETE FROM cases WHERE case_id IN ('CASE-SCOPE-001', 'CASE-SCOPE-002', 'CASE-EMPTY-003')")
    cursor.execute("DELETE FROM recovered_files WHERE case_id IN ('CASE-SCOPE-001', 'CASE-SCOPE-002', 'CASE-EMPTY-003')")
    cursor.execute("DELETE FROM evidence WHERE case_id IN ('CASE-SCOPE-001', 'CASE-SCOPE-002', 'CASE-EMPTY-003')")
    cursor.execute("DELETE FROM audit_logs WHERE case_id IN ('CASE-SCOPE-001', 'CASE-SCOPE-002', 'CASE-EMPTY-003')")

    cursor.execute("""
        INSERT INTO cases (case_id, case_name, investigator_name, organization, description, status, created_at, updated_at)
        VALUES 
        ('CASE-SCOPE-001', 'Operation Alpha Triage', 'Agent Vance', 'Cyber Forensics Unit', 'Investigation of Alpha intrusion', 'ACTIVE', ?, ?),
        ('CASE-SCOPE-002', 'Operation Bravo Extraction', 'Agent Vance', 'Cyber Forensics Unit', 'Investigation of Bravo intrusion', 'ACTIVE', ?, ?),
        ('CASE-EMPTY-003', 'Operation Charlie Zero', 'Agent Vance', 'Cyber Forensics Unit', 'Zero-artifact forensic triage', 'OPEN', ?, ?)
    """, (now, now, now, now, now, now))

    # Evidence for CASE-SCOPE-001
    cursor.execute("""
        INSERT INTO evidence (evidence_id, case_id, name, source_path, file_size, sha256, md5, drive_type, format, intake_timestamp)
        VALUES ('EVD-A1', 'CASE-SCOPE-001', 'disk_alpha.img', 'evidence/disk_alpha.img', 1048576, 'aaa111222333444555666777888999000111222333444555666777888999000a', 'md5alpha', 'IMG', 'RAW', ?)
    """, (now,))

    # Recovered files for CASE-SCOPE-001
    cursor.execute("""
        INSERT INTO recovered_files (case_id, evidence_id, file_name, file_type, extension, start_offset, length_bytes, confidence_score, confidence_level, recovery_method, recovered_file_path, recovered_at, is_valid)
        VALUES 
        ('CASE-SCOPE-001', 'EVD-A1', 'case001_confidential_plan.docx', 'DOCX', 'docx', 2048, 45000, 95.0, 'High', 'Signature Carving', 'recovered/case001_confidential_plan.docx', ?, 1),
        ('CASE-SCOPE-001', 'EVD-A1', 'case001_finance_sheet.xlsx', 'XLSX', 'xlsx', 8192, 62000, 92.5, 'High', 'Signature Carving', 'recovered/case001_finance_sheet.xlsx', ?, 1)
    """, (now, now))

    # Audit log for CASE-SCOPE-001
    cursor.execute("""
        INSERT INTO audit_logs (event_id, timestamp, event_type, action, case_id, user, prev_hash, record_hash)
        VALUES ('EVT-A1', ?, 'ACQUISITION', 'IMAGE_INTAKE_ALPHA', 'CASE-SCOPE-001', 'Agent Vance', 'GENESIS', 'HASH-A1')
    """, (now,))

    # Evidence for CASE-SCOPE-002
    cursor.execute("""
        INSERT INTO evidence (evidence_id, case_id, name, source_path, file_size, sha256, md5, drive_type, format, intake_timestamp)
        VALUES ('EVD-B1', 'CASE-SCOPE-002', 'disk_bravo.img', 'evidence/disk_bravo.img', 2097152, 'bbb111222333444555666777888999000111222333444555666777888999000b', 'md5bravo', 'IMG', 'RAW', ?)
    """, (now,))

    # Recovered files for CASE-SCOPE-002
    cursor.execute("""
        INSERT INTO recovered_files (case_id, evidence_id, file_name, file_type, extension, start_offset, length_bytes, confidence_score, confidence_level, recovery_method, recovered_file_path, recovered_at, is_valid)
        VALUES 
        ('CASE-SCOPE-002', 'EVD-B1', 'case002_seized_evidence.png', 'PNG', 'png', 4096, 128000, 98.0, 'Very High', 'Carving', 'recovered/case002_seized_evidence.png', ?, 1)
    """, (now,))

    # Audit log for CASE-SCOPE-002
    cursor.execute("""
        INSERT INTO audit_logs (event_id, timestamp, event_type, action, case_id, user, prev_hash, record_hash)
        VALUES ('EVT-B1', ?, 'ACQUISITION', 'IMAGE_INTAKE_BRAVO', 'CASE-SCOPE-002', 'Agent Vance', 'GENESIS', 'HASH-B1')
    """, (now,))

    conn.commit()
    conn.close()
    print("[SETUP] Test cases and evidence provisioned successfully.")

def test_missing_case_rejection():
    print("\n--- Test 1: Rejection on Missing Case ID ---")
    client = TestClient(app)

    # Missing case_id (empty string)
    res = client.post("/api/reports/generate", json={"case_id": ""})
    assert res.status_code == 400, f"Expected 400, got {res.status_code}: {res.text}"
    data = res.json()
    assert "Please select a case before generating a report." in data.get("detail", ""), f"Unexpected error detail: {data}"
    print("[PASS] Empty case_id properly rejected with HTTP 400 and message.")

    # None / null case_id
    res = client.post("/api/reports/generate", json={"case_id": None})
    assert res.status_code == 400, f"Expected 400, got {res.status_code}: {res.text}"
    data = res.json()
    assert "Please select a case before generating a report." in data.get("detail", ""), f"Unexpected error detail: {data}"
    print("[PASS] Null case_id properly rejected with HTTP 400.")

def extract_pdf_text(pdf_path: Path) -> str:
    with open(pdf_path, "rb") as f:
        raw = f.read().decode("latin1", errors="ignore")
    # Normalize ReportLab wrapped text tokens
    return re.sub(r'\)\s*Tj[\s\S]*?\s*\(', '', raw)

def test_case_data_isolation():
    print("\n--- Test 2: Strict Case Data Isolation (CASE-SCOPE-001 vs CASE-SCOPE-002) ---")
    client = TestClient(app)

    # 1. Generate report for CASE-SCOPE-001
    res1 = client.post("/api/reports/generate", json={
        "case_id": "CASE-SCOPE-001",
        "title": "Alpha Triage Dossier",
        "format": "PDF"
    })
    assert res1.status_code == 200, f"Generate CASE-SCOPE-001 failed: {res1.text}"
    data1 = res1.json()
    pdf_path_1 = Path(data1["file_path"])
    assert pdf_path_1.exists(), f"PDF not found: {pdf_path_1}"
    assert re.match(r"ForensiVault_CASE-SCOPE-001_Forensic_Report_REP-[A-Za-z0-9_\-]+\.pdf", pdf_path_1.name), f"Bad filename: {pdf_path_1.name}"

    pdf_str_1 = extract_pdf_text(pdf_path_1)
    assert "CASE-SCOPE-001" in pdf_str_1, "CASE-SCOPE-001 not found in PDF"
    assert "case001_confidential_plan.docx" in pdf_str_1, "case001_confidential_plan.docx not found in PDF 1"
    assert "case001_finance_sheet.xlsx" in pdf_str_1, "case001_finance_sheet.xlsx not found in PDF 1"
    assert "case002_seized_evidence.png" not in pdf_str_1, "CRITICAL LEAK: case002_seized_evidence.png found in PDF 1!"
    print(f"[PASS] Report 1 ({pdf_path_1.name}) contains CASE-SCOPE-001 items and strictly ZERO CASE-SCOPE-002 items.")

    # 2. Generate report for CASE-SCOPE-002
    res2 = client.post("/api/reports/generate", json={
        "case_id": "CASE-SCOPE-002",
        "title": "Bravo Extraction Dossier",
        "format": "PDF"
    })
    assert res2.status_code == 200, f"Generate CASE-SCOPE-002 failed: {res2.text}"
    data2 = res2.json()
    pdf_path_2 = Path(data2["file_path"])
    assert pdf_path_2.exists(), f"PDF not found: {pdf_path_2}"
    assert re.match(r"ForensiVault_CASE-SCOPE-002_Forensic_Report_REP-[A-Za-z0-9_\-]+\.pdf", pdf_path_2.name), f"Bad filename: {pdf_path_2.name}"

    pdf_str_2 = extract_pdf_text(pdf_path_2)
    assert "CASE-SCOPE-002" in pdf_str_2, "CASE-SCOPE-002 not found in PDF 2"
    assert "case002_seized_evidence.png" in pdf_str_2, "case002_seized_evidence.png not found in PDF 2"
    assert "case001_confidential_plan.docx" not in pdf_str_2, "CRITICAL LEAK: case001_confidential_plan.docx found in PDF 2!"
    assert "case001_finance_sheet.xlsx" not in pdf_str_2, "CRITICAL LEAK: case001_finance_sheet.xlsx found in PDF 2!"
    print(f"[PASS] Report 2 ({pdf_path_2.name}) contains CASE-SCOPE-002 items and strictly ZERO CASE-SCOPE-001 items.")

def test_empty_case_handling():
    print("\n--- Test 3: Zero-Artifact Case Handling (CASE-EMPTY-003) ---")
    client = TestClient(app)

    res3 = client.post("/api/reports/generate", json={
        "case_id": "CASE-EMPTY-003",
        "title": "Zero Artifact Investigation",
        "format": "PDF"
    })
    assert res3.status_code == 200, f"Generate CASE-EMPTY-003 failed: {res3.text}"
    data3 = res3.json()
    pdf_path_3 = Path(data3["file_path"])
    assert pdf_path_3.exists(), f"PDF not found: {pdf_path_3}"
    assert re.match(r"ForensiVault_CASE-EMPTY-003_Forensic_Report_REP-[A-Za-z0-9_\-]+\.pdf", pdf_path_3.name), f"Bad filename: {pdf_path_3.name}"

    pdf_str_3 = extract_pdf_text(pdf_path_3)
    assert "No recovered files were recorded for this case." in pdf_str_3, "Missing expected zero recovered files message"
    assert "No evidence records associated with this case." in pdf_str_3, "Missing expected zero evidence message"
    assert "No audit log records recorded for this case." in pdf_str_3, "Missing expected zero audit logs message"
    # Ensure NO items from other cases leaked
    assert "case001_confidential_plan.docx" not in pdf_str_3, "Leak in empty case!"
    assert "case002_seized_evidence.png" not in pdf_str_3, "Leak in empty case!"
    print(f"[PASS] Zero-artifact case report verified with explicit empty notices and zero leaks.")

def test_reports_api_filtering():
    print("\n--- Test 4: Report Listing and Filtering ---")
    client = TestClient(app)

    # Filter by CASE-SCOPE-001
    res = client.get("/api/reports?case_id=CASE-SCOPE-001")
    assert res.status_code == 200
    reports = res.json().get("reports", [])
    assert len(reports) >= 1
    for r in reports:
        assert r.get("case_id") == "CASE-SCOPE-001", f"Expected CASE-SCOPE-001, got {r.get('case_id')}"
    print(f"[PASS] Filtered reports list contains only CASE-SCOPE-001 reports.")

    # Download verification
    rep = reports[0]
    download_res = client.get(f"/api/reports/download/{rep['report_id']}")
    assert download_res.status_code == 200
    assert download_res.content[:5] == b"%PDF-", "Download does not begin with %PDF-"
    print(f"[PASS] Report download verified for {rep['report_id']}.")

if __name__ == "__main__":
    setup_test_fixtures()
    test_missing_case_rejection()
    test_case_data_isolation()
    test_empty_case_handling()
    test_reports_api_filtering()
    print("\n========================================================")
    print(">>> ALL CASE-SCOPED REPORT VERIFICATION TESTS PASSED <<<")
    print("========================================================")
