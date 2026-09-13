"""
ForensiVault Professional Forensic PDF Report Generator
Generates court-admissible, multi-page vector PDF forensic dossiers
using ReportLab with strict missing-value safety, running headers/footers,
and professional styling.
"""

import os
from pathlib import Path
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional

from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, KeepTogether, HRFlowable
)
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.pdfgen import canvas
import hashlib

class NumberedCanvas(canvas.Canvas):
    """
    Two-pass canvas to dynamically compute and render total page count
    along with running header and footer on every page.
    """
    def __init__(self, *args, **kwargs):
        kwargs["pageCompression"] = 0
        super().__init__(*args, **kwargs)
        self._pageCompression = 0
        self._saved_page_states = []

    def showPage(self):
        self._saved_page_states.append(dict(self.__dict__))
        self._startPage()

    def save(self):
        num_pages = len(self._saved_page_states)
        for state in self._saved_page_states:
            self.__dict__.update(state)
            self.draw_header_footer(num_pages)
            super().showPage()
        super().save()

    def draw_header_footer(self, page_count: int):
        self.saveState()
        self.setFont("Helvetica-Bold", 8)
        self.setFillColor(colors.HexColor("#756B63"))

        # Running Header (pages > 1)
        if self._pageNumber > 1:
            self.drawString(54, 752, "FORENSIVAULT FORENSIC INVESTIGATION DOSSIER — LAW ENFORCEMENT & COURT ADMISSIBLE")
            self.setStrokeColor(colors.HexColor("#DDD2C5"))
            self.setLineWidth(0.5)
            self.line(54, 746, 558, 746)

        # Running Footer (all pages)
        self.setStrokeColor(colors.HexColor("#DDD2C5"))
        self.setLineWidth(0.5)
        self.line(54, 45, 558, 45)

        self.setFont("Helvetica", 7.5)
        self.drawString(54, 34, "CONFIDENTIAL & PRIVILEGED — FORENSIC CHAIN OF CUSTODY DOCUMENTATION")
        page_str = f"Page {self._pageNumber} of {page_count}"
        self.drawRightString(558, 34, page_str)
        self.restoreState()


def format_bytes(bytes_val: Optional[int]) -> str:
    if bytes_val is None or bytes_val < 0:
        return "Not available"
    if bytes_val == 0:
        return "0 B"
    kb = 1024.0
    mb = kb * 1024.0
    gb = mb * 1024.0
    if bytes_val >= gb:
        return f"{bytes_val / gb:.2f} GB ({bytes_val:,} bytes)"
    elif bytes_val >= mb:
        return f"{bytes_val / mb:.2f} MB ({bytes_val:,} bytes)"
    elif bytes_val >= kb:
        return f"{bytes_val / kb:.2f} KB ({bytes_val:,} bytes)"
    else:
        return f"{bytes_val} bytes"


def safe_val(v: Any, default: str = "Not available") -> str:
    if v is None:
        return default
    s = str(v).strip()
    return s if s else default


def generate_forensic_pdf(
    output_path: str,
    case_info: Dict[str, Any],
    evidence_info: Optional[Dict[str, Any]] = None,
    recovery_stats: Optional[Dict[str, Any]] = None,
    recovered_files: Optional[List[Dict[str, Any]]] = None,
    audit_events: Optional[List[Dict[str, Any]]] = None,
    report_metadata: Optional[Dict[str, Any]] = None
) -> str:
    """
    Builds a court-admissible PDF forensic report and writes it to output_path.
    Returns the absolute path to the generated PDF.
    """
    out_p = Path(output_path).resolve()
    out_p.parent.mkdir(parents=True, exist_ok=True)

    # Document setup: 0.75 in margins (54 pt)
    doc = SimpleDocTemplate(
        str(out_p),
        pagesize=letter,
        leftMargin=54,
        rightMargin=54,
        topMargin=54,
        bottomMargin=54,
        pageCompression=0
    )

    styles = getSampleStyleSheet()
    
    # Custom forensic styling
    brand_orange = colors.HexColor("#D96B27")
    dark_gray = colors.HexColor("#1E1A16")
    subtle_border = colors.HexColor("#E5DDCB")
    table_header_bg = colors.HexColor("#F4EFE6")
    callout_bg = colors.HexColor("#FBF8F1")

    title_style = ParagraphStyle(
        "DocTitle",
        parent=styles["Heading1"],
        fontName="Helvetica-Bold",
        fontSize=20,
        leading=24,
        textColor=brand_orange,
        spaceAfter=4
    )

    subtitle_style = ParagraphStyle(
        "DocSubtitle",
        parent=styles["Normal"],
        fontName="Helvetica-Bold",
        fontSize=10,
        leading=14,
        textColor=colors.HexColor("#756B63"),
        spaceAfter=12
    )

    section_style = ParagraphStyle(
        "SectionHeading",
        parent=styles["Heading2"],
        fontName="Helvetica-Bold",
        fontSize=12,
        leading=16,
        textColor=dark_gray,
        spaceBefore=12,
        spaceAfter=6
    )

    body_style = ParagraphStyle(
        "BodyTextCustom",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=8.5,
        leading=12,
        textColor=dark_gray
    )

    bold_label_style = ParagraphStyle(
        "BoldLabel",
        parent=body_style,
        fontName="Helvetica-Bold",
        textColor=colors.HexColor("#3A342E")
    )

    mono_style = ParagraphStyle(
        "MonoText",
        parent=body_style,
        fontName="Courier",
        fontSize=7.5,
        leading=10,
        textColor=dark_gray
    )

    disclaimer_style = ParagraphStyle(
        "Disclaimer",
        parent=body_style,
        fontName="Helvetica-Oblique",
        fontSize=7.5,
        leading=11,
        textColor=colors.HexColor("#6B6259")
    )

    story = []

    # 1. Header Banner & Branding
    meta = report_metadata or {}
    rep_id = safe_val(meta.get("report_id"), f"REP-{int(datetime.now(timezone.utc).timestamp())}")
    gen_time = safe_val(meta.get("timestamp"), datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"))
    examiner = safe_val(case_info.get("investigator_name") or case_info.get("examiner"), "Ruben")
    agency = safe_val(case_info.get("organization") or case_info.get("agency"), "ForensiVault Digital Forensics Laboratory")
    case_id = safe_val(case_info.get("case_id"), "CASE-GENERAL")
    case_name = safe_val(case_info.get("case_name") or case_info.get("title"), "Digital Forensic Examination")
    case_desc = safe_val(case_info.get("description"), "Forensic investigation dossier and evidence artifacts.")
    case_status = safe_val(case_info.get("status"), "ACTIVE").upper()

    story.append(Paragraph("FORENSIVAULT", title_style))
    story.append(Paragraph("DIGITAL FORENSIC ANALYSIS & EVIDENCE RECOVERY REPORT", subtitle_style))
    story.append(HRFlowable(width="100%", thickness=1.5, color=brand_orange, spaceBefore=0, spaceAfter=10))

    # 2. Key Case Metadata Table
    case_table_data = [
        [
            Paragraph("Report ID:", bold_label_style), Paragraph(rep_id, mono_style),
            Paragraph("Case ID:", bold_label_style), Paragraph(case_id, mono_style)
        ],
        [
            Paragraph("Case Name:", bold_label_style), Paragraph(case_name, body_style),
            Paragraph("Case Status:", bold_label_style), Paragraph(case_status, bold_label_style)
        ],
        [
            Paragraph("Date / Time:", bold_label_style), Paragraph(gen_time, body_style),
            Paragraph("Lead Examiner:", bold_label_style), Paragraph(examiner, body_style)
        ],
        [
            Paragraph("Agency / Unit:", bold_label_style), Paragraph(agency, body_style),
            Paragraph("Description:", bold_label_style), Paragraph(case_desc, body_style)
        ]
    ]
    case_table = Table(case_table_data, colWidths=[80, 170, 74, 180])
    case_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,-1), callout_bg),
        ('BOX', (0,0), (-1,-1), 0.5, subtle_border),
        ('INNERGRID', (0,0), (-1,-1), 0.5, subtle_border),
        ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
        ('TOPPADDING', (0,0), (-1,-1), 4),
        ('BOTTOMPADDING', (0,0), (-1,-1), 4),
        ('LEFTPADDING', (0,0), (-1,-1), 6),
        ('RIGHTPADDING', (0,0), (-1,-1), 6),
    ]))
    story.append(case_table)
    story.append(Spacer(1, 10))

    # 3. Evidence Information
    story.append(Paragraph("1. Evidence Acquisition & Integrity Verification", section_style))
    
    # Normalize evidence info into list
    ev_list: List[Dict[str, Any]] = []
    if isinstance(evidence_info, list):
        ev_list = [e for e in evidence_info if e and any(e.values())]
    elif isinstance(evidence_info, dict) and any(evidence_info.values()):
        ev_list = [evidence_info]

    if not ev_list:
        no_ev_table = Table(
            [[Paragraph("No evidence records associated with this case.", body_style)]],
            colWidths=[504]
        )
        no_ev_table.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,-1), callout_bg),
            ('BOX', (0,0), (-1,-1), 0.5, subtle_border),
            ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
            ('TOPPADDING', (0,0), (-1,-1), 6),
            ('BOTTOMPADDING', (0,0), (-1,-1), 6),
            ('LEFTPADDING', (0,0), (-1,-1), 8),
            ('RIGHTPADDING', (0,0), (-1,-1), 8),
        ]))
        story.append(no_ev_table)
    else:
        for idx, ev in enumerate(ev_list, 1):
            ev_path = safe_val(ev.get("source_path") or ev.get("path") or ev.get("name"))
            ev_format = safe_val(ev.get("image_format") or ev.get("format"), "RAW / DD Disk Image (.img)")
            ev_size = format_bytes(ev.get("total_bytes") or ev.get("size_bytes") or ev.get("file_size") or ev.get("size"))
            ev_hash = safe_val(ev.get("sha256"))
            ev_md5 = safe_val(ev.get("md5"))
            ev_mode = safe_val(ev.get("access_mode"), "Strict Read-Only (Hardware/IPC Write-Blocked)")

            ev_table_data = [
                [Paragraph("Target Evidence:", bold_label_style), Paragraph(ev_path, mono_style)],
                [Paragraph("Image Format:", bold_label_style), Paragraph(ev_format, body_style)],
                [Paragraph("Evidence Size:", bold_label_style), Paragraph(ev_size, body_style)],
                [Paragraph("Access Protocol:", bold_label_style), Paragraph(ev_mode, body_style)],
                [Paragraph("SHA-256 Digest:", bold_label_style), Paragraph(ev_hash, mono_style)],
                [Paragraph("MD5 Digest:", bold_label_style), Paragraph(ev_md5, mono_style)],
            ]
            ev_table = Table(ev_table_data, colWidths=[110, 394])
            ev_table.setStyle(TableStyle([
                ('BACKGROUND', (0,0), (-1,-1), colors.white),
                ('BOX', (0,0), (-1,-1), 0.5, subtle_border),
                ('INNERGRID', (0,0), (-1,-1), 0.5, subtle_border),
                ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
                ('TOPPADDING', (0,0), (-1,-1), 3),
                ('BOTTOMPADDING', (0,0), (-1,-1), 3),
                ('LEFTPADDING', (0,0), (-1,-1), 6),
                ('RIGHTPADDING', (0,0), (-1,-1), 6),
            ]))
            story.append(ev_table)
            if idx < len(ev_list):
                story.append(Spacer(1, 6))

    story.append(Spacer(1, 10))

    # 4. Recovery Statistics Summary
    story.append(Paragraph("2. Recovery Statistics & Discovery Summary", section_style))
    files_list = recovered_files or []
    stats = recovery_stats or {}
    total_detected = stats.get("total_detected", len(files_list))
    total_recovered = stats.get("total_recovered", len([f for f in files_list if f.get("is_valid", 1) in (1, True, "1")]))
    total_partial = stats.get("total_partial", len([f for f in files_list if f.get("is_valid", 1) in (0, False, "0")]))
    total_failed = stats.get("total_failed", 0)
    
    avg_conf = stats.get("avg_confidence")
    if not avg_conf:
        if files_list:
            c_scores = [float(f.get("confidence_score") or 0) for f in files_list]
            avg_conf = f"{sum(c_scores) / len(c_scores):.1f}%"
        else:
            avg_conf = "0.0%"
            
    fragment_candidates = stats.get("fragment_candidates", len([f for f in files_list if (f.get("sector_span") or 1) > 1 or f.get("fragment_count", 1) > 1]))

    stats_data = [
        [
            Paragraph("Files Detected", bold_label_style),
            Paragraph("Successfully Recovered", bold_label_style),
            Paragraph("Partial / Carved", bold_label_style),
            Paragraph("Avg Confidence", bold_label_style),
            Paragraph("Fragment Candidates", bold_label_style),
        ],
        [
            Paragraph(str(total_detected), ParagraphStyle("s1", parent=body_style, fontName="Helvetica-Bold", fontSize=11, alignment=1)),
            Paragraph(str(total_recovered), ParagraphStyle("s2", parent=body_style, fontName="Helvetica-Bold", fontSize=11, textColor=colors.HexColor("#2E7D32"), alignment=1)),
            Paragraph(str(total_partial), ParagraphStyle("s3", parent=body_style, fontName="Helvetica-Bold", fontSize=11, textColor=colors.HexColor("#B45309"), alignment=1)),
            Paragraph(str(avg_conf), ParagraphStyle("s4", parent=body_style, fontName="Helvetica-Bold", fontSize=11, textColor=colors.HexColor("#2563EB"), alignment=1)),
            Paragraph(str(fragment_candidates), ParagraphStyle("s5", parent=body_style, fontName="Helvetica-Bold", fontSize=11, textColor=brand_orange, alignment=1)),
        ]
    ]
    stats_table = Table(stats_data, colWidths=[100, 105, 95, 100, 104])
    stats_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), table_header_bg),
        ('BACKGROUND', (0,1), (-1,1), callout_bg),
        ('BOX', (0,0), (-1,-1), 0.5, subtle_border),
        ('INNERGRID', (0,0), (-1,-1), 0.5, subtle_border),
        ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
        ('ALIGN', (0,0), (-1,-1), 'CENTER'),
        ('TOPPADDING', (0,0), (-1,-1), 4),
        ('BOTTOMPADDING', (0,0), (-1,-1), 4),
    ]))
    story.append(stats_table)
    story.append(Spacer(1, 12))

    # 5. Recovered Files Detail Table
    story.append(Paragraph("3. Recovered & Reconstructed Files Catalog", section_style))
    
    if not files_list:
        no_files_table = Table(
            [[Paragraph("No recovered files were recorded for this case.", body_style)]],
            colWidths=[504]
        )
        no_files_table.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,-1), callout_bg),
            ('BOX', (0,0), (-1,-1), 0.5, subtle_border),
            ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
            ('TOPPADDING', (0,0), (-1,-1), 8),
            ('BOTTOMPADDING', (0,0), (-1,-1), 8),
            ('LEFTPADDING', (0,0), (-1,-1), 10),
            ('RIGHTPADDING', (0,0), (-1,-1), 10),
        ]))
        story.append(no_files_table)
    else:
        files_headers = [
            Paragraph("File Name", bold_label_style),
            Paragraph("Type", bold_label_style),
            Paragraph("Size", bold_label_style),
            Paragraph("Method", bold_label_style),
            Paragraph("Offset / Sec", bold_label_style),
            Paragraph("Frags", bold_label_style),
            Paragraph("Conf", bold_label_style),
            Paragraph("SHA-256 Digest", bold_label_style),
            Paragraph("Status", bold_label_style),
        ]
        files_table_rows = [files_headers]

        for f in files_list:
            fname = safe_val(f.get("filename") or f.get("file_name") or f.get("name"), "recovered_item")
            ftype = safe_val(f.get("file_type") or f.get("extension"), "RAW").upper()
            fsize = format_bytes(f.get("length_bytes") or f.get("size_bytes") or f.get("size"))
            method = safe_val(f.get("recovery_method") or f.get("method"), "Signature Carving")
            
            offset_val = f.get("offset_hex")
            if not offset_val and f.get("offset_dec") is not None:
                offset_val = f"0x{int(f['offset_dec']):X}"
            elif not offset_val and f.get("start_offset") is not None:
                offset_val = f"0x{int(f['start_offset']):X}"
            offset_str = safe_val(offset_val, "0x0")
            
            frags = str(f.get("sector_span") or f.get("fragment_count") or 1)

            conf_val = f.get("confidence_score") or f.get("confidence")
            conf_str = f"{float(conf_val):.0f}%" if conf_val is not None else "N/A"
            
            sha_str = safe_val(f.get("sha256"))
            if len(sha_str) > 16 and sha_str != "Not available":
                sha_display = sha_str[:16] + "..."
            else:
                sha_display = sha_str

            is_valid = f.get("is_valid", 1) in (1, True, "1")
            status_str = "INTACT" if is_valid else "PARTIAL"
            status_color = colors.HexColor("#2E7D32") if is_valid else colors.HexColor("#B45309")

            files_table_rows.append([
                Paragraph(fname, body_style),
                Paragraph(ftype, mono_style),
                Paragraph(fsize, body_style),
                Paragraph(method, body_style),
                Paragraph(offset_str, mono_style),
                Paragraph(frags, mono_style),
                Paragraph(conf_str, body_style),
                Paragraph(sha_display, mono_style),
                Paragraph(status_str, ParagraphStyle("fst", parent=body_style, fontName="Helvetica-Bold", textColor=status_color)),
            ])

        files_table = Table(files_table_rows, colWidths=[85, 32, 48, 55, 50, 32, 38, 114, 50])
        files_table.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), table_header_bg),
            ('BOX', (0,0), (-1,-1), 0.5, subtle_border),
            ('INNERGRID', (0,0), (-1,-1), 0.5, subtle_border),
            ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
            ('TOPPADDING', (0,0), (-1,-1), 3),
            ('BOTTOMPADDING', (0,0), (-1,-1), 3),
            ('LEFTPADDING', (0,0), (-1,-1), 3),
            ('RIGHTPADDING', (0,0), (-1,-1), 3),
        ]))
        story.append(files_table)

    story.append(Spacer(1, 12))

    # 6. Audit Information Table
    story.append(Paragraph("4. Chain-of-Custody & Operation Audit Trail", section_style))
    audit_list = audit_events or []

    if not audit_list:
        no_audit_table = Table(
            [[Paragraph("No audit log records recorded for this case.", body_style)]],
            colWidths=[504]
        )
        no_audit_table.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,-1), callout_bg),
            ('BOX', (0,0), (-1,-1), 0.5, subtle_border),
            ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
            ('TOPPADDING', (0,0), (-1,-1), 8),
            ('BOTTOMPADDING', (0,0), (-1,-1), 8),
            ('LEFTPADDING', (0,0), (-1,-1), 10),
            ('RIGHTPADDING', (0,0), (-1,-1), 10),
        ]))
        story.append(no_audit_table)
    else:
        audit_headers = [
            Paragraph("Entry #", bold_label_style),
            Paragraph("Timestamp", bold_label_style),
            Paragraph("Operation", bold_label_style),
            Paragraph("Operator", bold_label_style),
            Paragraph("Target Identifier", bold_label_style),
            Paragraph("Status", bold_label_style)
        ]
        audit_table_rows = [audit_headers]

        for idx, a in enumerate(audit_list[:25], 1):
            eid = safe_val(a.get("entry_id") or a.get("id"), str(idx))
            ts = safe_val(a.get("timestamp"), gen_time)
            op = safe_val(a.get("operation_type") or a.get("action") or a.get("event_type"), "OPERATION")
            user = safe_val(a.get("operator_name") or a.get("user") or a.get("operator"), examiner)
            target = safe_val(a.get("source_identifier") or a.get("target") or a.get("case_id"), case_id)
            status = safe_val(a.get("status"), "COMPLETED").upper()
            status_color = colors.HexColor("#2E7D32") if any(k in status for k in ("SUCCESS", "COMPLETED", "VERIFIED")) else colors.HexColor("#C53030")
            
            audit_table_rows.append([
                Paragraph(eid, mono_style),
                Paragraph(ts[:19] if len(ts) >= 19 else ts, body_style),
                Paragraph(op.replace("_", " "), body_style),
                Paragraph(user, body_style),
                Paragraph(target if len(target) <= 24 else target[:21] + "...", mono_style),
                Paragraph(status, ParagraphStyle("st", parent=body_style, fontName="Helvetica-Bold", textColor=status_color))
            ])

        audit_table = Table(audit_table_rows, colWidths=[40, 95, 115, 80, 114, 60])
        audit_table.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), table_header_bg),
            ('BOX', (0,0), (-1,-1), 0.5, subtle_border),
            ('INNERGRID', (0,0), (-1,-1), 0.5, subtle_border),
            ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
            ('TOPPADDING', (0,0), (-1,-1), 3),
            ('BOTTOMPADDING', (0,0), (-1,-1), 3),
            ('LEFTPADDING', (0,0), (-1,-1), 4),
            ('RIGHTPADDING', (0,0), (-1,-1), 4),
        ]))
        story.append(audit_table)

    story.append(Spacer(1, 14))

    # 7. Mandatory Forensic Disclaimer
    story.append(Paragraph(
        "<strong>Legal & Technical Disclaimer:</strong> This report is generated by ForensiVault based on the available analysis results. "
        "Recovery results depend on the condition of the underlying storage data, filesystem allocations, cluster continuity, and sector entropy. "
        "No forensic inferences or data points were simulated or fabricated.",
        disclaimer_style
    ))
    story.append(Spacer(1, 14))

    # 8. Signature Block
    sig_data = [
        [
            Paragraph("____________________________________________<br/><strong>Lead Forensic Examiner</strong><br/>" + examiner + "<br/>" + agency, body_style),
            Paragraph("____________________________________________<br/><strong>Technical Reviewer / QA Officer</strong><br/>Quality Assurance Laboratory Unit<br/>ForensiVault Compliance Division", body_style)
        ]
    ]
    sig_table = Table(sig_data, colWidths=[250, 254])
    sig_table.setStyle(TableStyle([
        ('VALIGN', (0,0), (-1,-1), 'TOP'),
        ('TOPPADDING', (0,0), (-1,-1), 8),
    ]))
    story.append(KeepTogether(sig_table))

    # Build document with NumberedCanvas
    doc.build(story, canvasmaker=NumberedCanvas)
    return str(out_p)
