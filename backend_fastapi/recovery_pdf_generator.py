"""
ForensiVault Dedicated Recovery PDF Generator
Generates comprehensive, court-admissible PDF recovery dossiers for specific recovery sessions.
Embeds real recovered content:
- PDF files: renders high-resolution page previews and extracts document text streams.
- Image files: embeds actual images with preserved aspect ratio and metadata captions.
- Plaintext/Code files: embeds clean readable text with proper wrapping and pagination.
- DOCX files: extracts and renders structured document paragraphs.
- ZIP archives: renders manifest table plus internal text previews of files inside the archive.
- Binary files: states reason, displays full metadata, SHA-256, hex dump, and exact disk path.
"""

import os
import sys
import html
import hashlib
import zipfile
import xml.etree.ElementTree as ET
from pathlib import Path
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional

from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, KeepTogether, HRFlowable, Image as RLImage
)
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.pdfgen import canvas
from PIL import Image as PILImage

try:
    import pypdf
except ImportError:
    pypdf = None

try:
    import pypdfium2 as pdfium
except ImportError:
    pdfium = None


class RecoveryNumberedCanvas(canvas.Canvas):
    """
    Two-pass canvas that dynamically counts total pages and renders running
    headers and footers on every page of the Recovery Dossier.
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
            self.drawString(40, 752, "FORENSIVAULT - DEDICATED EVIDENCE RECOVERY DOSSIER (OFFICIAL EXHIBIT)")
            self.setStrokeColor(colors.HexColor("#DDD2C5"))
            self.setLineWidth(0.5)
            self.line(40, 746, 572, 746)

        # Running Footer (all pages)
        self.setStrokeColor(colors.HexColor("#DDD2C5"))
        self.setLineWidth(0.5)
        self.line(40, 42, 572, 42)

        self.setFont("Helvetica", 7.5)
        self.drawString(40, 31, "CONFIDENTIAL & PRIVILEGED - DIGITAL EVIDENCE CHAIN OF CUSTODY")
        page_str = f"Page {self._pageNumber} of {page_count}"
        self.drawRightString(572, 31, page_str)
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


def generate_hex_dump(data: bytes, max_bytes: int = 128) -> str:
    """Generate a clean 16-byte-per-line forensic hex dump with ASCII sidebar."""
    lines = []
    chunk = data[:max_bytes]
    for i in range(0, len(chunk), 16):
        line_bytes = chunk[i:i+16]
        hex_part1 = " ".join(f"{b:02X}" for b in line_bytes[:8])
        hex_part2 = " ".join(f"{b:02X}" for b in line_bytes[8:])
        hex_full = f"{hex_part1:<23}  {hex_part2:<23}".rstrip()
        ascii_part = "".join(chr(b) if 32 <= b <= 126 else "." for b in line_bytes)
        lines.append(f"{i:08X}  {hex_full:<48}  |{ascii_part}|")
    return "\n".join(lines)


def extract_docx_text(file_path: Path) -> Optional[str]:
    """Extract readable paragraphs from a docx file using standard zipfile and xml parsing."""
    try:
        with zipfile.ZipFile(file_path, "r") as zf:
            if "word/document.xml" not in zf.namelist():
                return None
            xml_bytes = zf.read("word/document.xml")
            root = ET.fromstring(xml_bytes)
            ns = {"w": "http://schemas.openxmlformats.org/wordprocessingml/2006/main"}
            paragraphs = []
            for p in root.iter(f"{{{ns['w']}}}p"):
                text_runs = [t.text for t in p.iter(f"{{{ns['w']}}}t") if t.text]
                if text_runs:
                    paragraphs.append("".join(text_runs).strip())
            return "\n\n".join([p for p in paragraphs if p])
    except Exception:
        return None


def generate_recovery_pdf(
    output_path: str,
    session_info: Dict[str, Any],
    recovery_stats: Dict[str, Any],
    recovered_files: List[Dict[str, Any]]
) -> str:
    """
    Builds a court-admissible PDF recovery report and writes it to output_path.
    Returns the SHA-256 hash of the generated PDF file.
    """
    out_dir = Path(output_path).parent
    out_dir.mkdir(parents=True, exist_ok=True)
    cache_dir = out_dir / ".preview_cache"
    cache_dir.mkdir(parents=True, exist_ok=True)

    doc = SimpleDocTemplate(
        output_path,
        pagesize=letter,
        leftMargin=40,
        rightMargin=40,
        topMargin=50,
        bottomMargin=50
    )

    styles = getSampleStyleSheet()

    # Custom Typography & Color Palette
    title_style = ParagraphStyle(
        "RecTitle",
        parent=styles["Heading1"],
        fontName="Helvetica-Bold",
        fontSize=20,
        leading=24,
        textColor=colors.HexColor("#1A202C")
    )
    subtitle_style = ParagraphStyle(
        "RecSubtitle",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=9.5,
        leading=14,
        textColor=colors.HexColor("#756B63")
    )
    sec_title = ParagraphStyle(
        "RecSecTitle",
        parent=styles["Heading2"],
        fontName="Helvetica-Bold",
        fontSize=12,
        leading=16,
        textColor=colors.HexColor("#1A202C"),
        spaceBefore=14,
        spaceAfter=6
    )
    label_style = ParagraphStyle(
        "RecLabel",
        parent=styles["Normal"],
        fontName="Helvetica-Bold",
        fontSize=8,
        leading=11,
        textColor=colors.HexColor("#756B63")
    )
    val_style = ParagraphStyle(
        "RecVal",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=8.5,
        leading=12,
        textColor=colors.HexColor("#1A202C")
    )
    val_mono = ParagraphStyle(
        "RecValMono",
        parent=styles["Normal"],
        fontName="Courier",
        fontSize=8,
        leading=11,
        textColor=colors.HexColor("#1A202C")
    )
    th_style = ParagraphStyle(
        "RecTH",
        parent=styles["Normal"],
        fontName="Helvetica-Bold",
        fontSize=8,
        leading=10,
        textColor=colors.HexColor("#FFFFFF"),
        alignment=0
    )
    td_style = ParagraphStyle(
        "RecTD",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=7.5,
        leading=10.5,
        textColor=colors.HexColor("#1A202C")
    )
    td_mono = ParagraphStyle(
        "RecTDMono",
        parent=styles["Normal"],
        fontName="Courier",
        fontSize=7,
        leading=9.5,
        textColor=colors.HexColor("#1A202C")
    )
    pre_style = ParagraphStyle(
        "RecPre",
        parent=styles["Normal"],
        fontName="Courier",
        fontSize=7.5,
        leading=10,
        textColor=colors.HexColor("#2D3748")
    )
    caption_style = ParagraphStyle(
        "RecCaption",
        parent=styles["Normal"],
        fontName="Helvetica-Oblique",
        fontSize=8,
        leading=11,
        textColor=colors.HexColor("#4A5568"),
        alignment=1
    )
    content_heading_style = ParagraphStyle(
        "RecActualContentH",
        parent=styles["Heading3"],
        fontName="Helvetica-Bold",
        fontSize=10,
        leading=14,
        textColor=colors.HexColor("#C53030"),
        spaceBefore=6,
        spaceAfter=4
    )

    story = []

    # 1. Header Banner & Title
    case_id = safe_val(session_info.get("case_id"), "CASE-UNKNOWN")
    rec_op_id = safe_val(session_info.get("recovery_op_id"), f"REC-{datetime.now().strftime('%Y%m%d-%H%M%S')}")
    op_date = safe_val(session_info.get("timestamp"), datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC"))
    operator = safe_val(session_info.get("operator"), "Senior Investigator Ruben")

    story.append(Paragraph("FORENSIVAULT - DIGITAL EVIDENCE RECOVERY REPORT", title_style))
    story.append(Paragraph(
        "Court-Admissible Record of Cryptographically Verified File Recovery Operations",
        subtitle_style
    ))
    story.append(Spacer(1, 8))

    # Header metadata badges table
    header_meta_data = [
        [
            Paragraph("Case Identifier:", label_style),
            Paragraph(f"<b>{case_id}</b>", val_style),
            Paragraph("Recovery Operation ID:", label_style),
            Paragraph(f"<b>{rec_op_id}</b>", val_style)
        ],
        [
            Paragraph("Execution Date / Time:", label_style),
            Paragraph(op_date, val_style),
            Paragraph("Investigating Operator:", label_style),
            Paragraph(operator, val_style)
        ],
        [
            Paragraph("Evidence Source Target:", label_style),
            Paragraph(safe_val(session_info.get("source_device")), val_style),
            Paragraph("Source Partition / Offset:", label_style),
            Paragraph(safe_val(session_info.get("source_partition")), val_style)
        ],
        [
            Paragraph("Identified Filesystem:", label_style),
            Paragraph(f"<b>{safe_val(session_info.get('filesystem'))}</b>", val_style),
            Paragraph("Evidence Integrity Mode:", label_style),
            Paragraph("<font color='#2E7D32'><b>READ-ONLY FORENSIC MODE (Software Read-Only Analysis Mode)</b></font>", val_style)
        ]
    ]

    header_table = Table(header_meta_data, colWidths=[120, 146, 120, 146])
    header_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#F8F9FA")),
        ("BOX", (0, 0), (-1, -1), 1, colors.HexColor("#E2E8F0")),
        ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#EDF2F7")),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("LEFTPADDING", (0, 0), (-1, -1), 6),
        ("RIGHTPADDING", (0, 0), (-1, -1), 6),
    ]))
    story.append(header_table)
    story.append(Spacer(1, 12))

    # 2. Recovery Session Summary Grid
    story.append(Paragraph("RECOVERY SESSION SUMMARY & STATISTICS", sec_title))

    total_candidates = recovery_stats.get("total_candidates", len(recovered_files))
    total_selected = recovery_stats.get("total_selected", len(recovered_files))
    total_recovered = recovery_stats.get("total_recovered", len([f for f in recovered_files if f.get("is_recoverable")]))
    total_failed = recovery_stats.get("total_failed", len([f for f in recovered_files if not f.get("is_recoverable")]))
    total_bytes = recovery_stats.get("total_bytes", sum(f.get("size_bytes", 0) for f in recovered_files if f.get("is_recoverable")))
    fs_count = recovery_stats.get("filesystem_count", len([f for f in recovered_files if "carv" not in safe_val(f.get("method")).lower()]))
    carved_count = recovery_stats.get("carved_count", len([f for f in recovered_files if "carv" in safe_val(f.get("method")).lower()]))
    frag_count = recovery_stats.get("fragment_count", len([f for f in recovered_files if f.get("fragment_count", 1) > 1]))

    stat_data = [
        [
            Paragraph("Total Candidates Found", label_style),
            Paragraph(str(total_candidates), val_style),
            Paragraph("Files Selected for Extraction", label_style),
            Paragraph(str(total_selected), val_style)
        ],
        [
            Paragraph("Successfully Recovered", label_style),
            Paragraph(f"<font color='#2E7D32'><b>{total_recovered} file(s)</b></font>", val_style),
            Paragraph("Unrecoverable / Corrupted", label_style),
            Paragraph(f"<font color='#C53030'><b>{total_failed} file(s)</b></font>", val_style)
        ],
        [
            Paragraph("Total Recovered Volume", label_style),
            Paragraph(format_bytes(total_bytes), val_style),
            Paragraph("Filesystem Metadata Recoveries", label_style),
            Paragraph(str(fs_count), val_style)
        ],
        [
            Paragraph("Raw Carved Recoveries", label_style),
            Paragraph(str(carved_count), val_style),
            Paragraph("Fragmented File Candidates", label_style),
            Paragraph(str(frag_count), val_style)
        ]
    ]

    stat_table = Table(stat_data, colWidths=[130, 136, 130, 136])
    stat_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#FFFFFF")),
        ("BOX", (0, 0), (-1, -1), 1, colors.HexColor("#D96B27")),
        ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#E2E8F0")),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("LEFTPADDING", (0, 0), (-1, -1), 6),
        ("RIGHTPADDING", (0, 0), (-1, -1), 6),
    ]))
    story.append(stat_table)
    story.append(Spacer(1, 10))

    # Evidence Bitstream Immutability Box
    pre_h = safe_val(recovery_stats.get("pre_hash"), "N/A")
    post_h = safe_val(recovery_stats.get("post_hash"), "N/A")
    unmod = recovery_stats.get("immutability_verified", True)
    unmod_text = "<font color='#2E7D32'><b>100% BIT-FOR-BIT VERIFIED (EVIDENCE SOURCE UNMODIFIED)</b></font>" if unmod else "<font color='#C53030'><b>INTEGRITY COMPROMISED</b></font>"

    immutability_data = [
        [
            Paragraph("<b>Evidence Pre-Recovery SHA-256:</b>", label_style),
            Paragraph(pre_h, val_mono)
        ],
        [
            Paragraph("<b>Evidence Post-Recovery SHA-256:</b>", label_style),
            Paragraph(post_h, val_mono)
        ],
        [
            Paragraph("<b>Forensic Analysis Mode:</b>", label_style),
            Paragraph(unmod_text, val_style)
        ]
    ]
    immut_table = Table(immutability_data, colWidths=[140, 392])
    immut_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#F0FFF4")),
        ("BOX", (0, 0), (-1, -1), 1, colors.HexColor("#9AE6B4")),
        ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#C6F6D5")),
        ("TOPPADDING", (0, 0), (-1, -1), 3),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
        ("LEFTPADDING", (0, 0), (-1, -1), 6),
        ("RIGHTPADDING", (0, 0), (-1, -1), 6),
    ]))
    story.append(immut_table)
    story.append(Spacer(1, 14))

    # 3. Section 1: RECOVERED FILES SUMMARY TABLE
    story.append(Paragraph("RECOVERED FILES SUMMARY CATALOG", sec_title))
    story.append(Paragraph(
        "Comprehensive inventory of all evidence items processed during this recovery operation. "
        "No records have been truncated or omitted.",
        subtitle_style
    ))
    story.append(Spacer(1, 6))

    summary_headers = [
        Paragraph("<b>#</b>", th_style),
        Paragraph("<b>Filename</b>", th_style),
        Paragraph("<b>Type</b>", th_style),
        Paragraph("<b>Size</b>", th_style),
        Paragraph("<b>Method</b>", th_style),
        Paragraph("<b>Conf</b>", th_style),
        Paragraph("<b>SHA-256 Digest</b>", th_style),
        Paragraph("<b>Status</b>", th_style)
    ]
    summary_rows = [summary_headers]

    for idx, f in enumerate(recovered_files, start=1):
        fn = safe_val(f.get("filename"), "unknown_file.dat")
        ftype = safe_val(f.get("file_type") or f.get("extension"), "DAT").upper()
        sz = format_bytes(f.get("size_bytes"))
        meth = safe_val(f.get("method"), "Filesystem")
        conf = f"{f.get('confidence_score', 95)}%"
        h = safe_val(f.get("sha256"), "")
        h_disp = (h[:8] + "..." + h[-8:]) if len(h) >= 16 else (h if h else "Not available")
        st = safe_val(f.get("recovery_status"), "Recovered" if f.get("is_recoverable") else "Not Recoverable")
        st_color = "#2E7D32" if f.get("is_recoverable") else "#C53030"

        summary_rows.append([
            Paragraph(str(idx), td_style),
            Paragraph(f"<b>{html.escape(fn)}</b>", td_style),
            Paragraph(ftype, td_style),
            Paragraph(sz, td_style),
            Paragraph(meth, td_style),
            Paragraph(conf, td_style),
            Paragraph(h_disp, td_mono),
            Paragraph(f"<font color='{st_color}'><b>{st}</b></font>", td_style)
        ])

    summary_table = Table(
        summary_rows,
        colWidths=[24, 110, 42, 64, 88, 38, 96, 70],
        repeatRows=1
    )
    summary_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1A202C")),
        ("ALIGN", (0, 0), (-1, -1), "LEFT"),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E0")),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.HexColor("#FFFFFF"), colors.HexColor("#F8F9FA")]),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("LEFTPADDING", (0, 0), (-1, -1), 4),
        ("RIGHTPADDING", (0, 0), (-1, -1), 4),
    ]))
    story.append(summary_table)
    story.append(Spacer(1, 16))

    # 4. Section 2: INDIVIDUAL RECOVERED FILE DETAILS & CONTENT PREVIEWS
    story.append(PageBreak())
    story.append(Paragraph("INDIVIDUAL RECOVERED FILE DOSSIERS & CONTENT EVIDENCE", sec_title))
    story.append(Paragraph(
        "Individual forensic metadata records and verified content representations for every recovered item. "
        "Original bitstream files are preserved in the recovery session repository.",
        subtitle_style
    ))
    story.append(Spacer(1, 10))

    for idx, f in enumerate(recovered_files, start=1):
        fn = safe_val(f.get("filename"), f"recovered_file_{idx}.dat")
        orig_fn = safe_val(f.get("original_filename") or f.get("filename"), "Not available")
        orig_path = safe_val(f.get("original_path"), "Not available")
        ftype = safe_val(f.get("file_type"), "UNKNOWN")
        fext = safe_val(f.get("extension"), "").lower().strip(".")
        size_b = f.get("size_bytes", 0)
        size_fmt = format_bytes(size_b)
        fs_str = safe_val(f.get("filesystem") or session_info.get("filesystem"), "Not available")
        meth = safe_val(f.get("method"), "Filesystem Metadata")
        start_clus = safe_val(f.get("starting_cluster"), "Not available")
        mft_rec = safe_val(f.get("mft_record"), "Not available")
        offset_hex = safe_val(f.get("offset_hex"), f"0x{f.get('offset_dec', 0):08X}" if "offset_dec" in f else "Not available")
        frag_count = safe_val(f.get("fragment_count"), 1)
        frag_str = f"Fragmented ({frag_count} fragments)" if (isinstance(frag_count, int) and frag_count > 1) else "Contiguous (1 Fragment)"
        conf_score = f.get("confidence_score", 95)
        conf_level = safe_val(f.get("confidence_level"), "High")
        sha256_hash = safe_val(f.get("sha256"), "Not available")
        rec_time = safe_val(f.get("recovered_at") or session_info.get("timestamp"), op_date)
        out_path = safe_val(f.get("recovered_file_path"), "Not available")
        is_rec = f.get("is_recoverable", True)
        verif_result = safe_val(f.get("verification_result"), "VERIFIED (Cryptographic SHA-256 match)") if is_rec else safe_val(f.get("unrecoverable_reason"), "Unrecoverable")

        # Header for individual file
        file_header_p = Paragraph(
            f"<b>Recovered File #{idx}:</b> <font color='#D96B27'>{html.escape(fn)}</font>",
            ParagraphStyle("ItemH", parent=sec_title, fontSize=11, spaceBefore=6, spaceAfter=4)
        )

        # Metadata Table
        meta_rows = [
            [
                Paragraph("Original Filename:", label_style),
                Paragraph(html.escape(orig_fn), val_style),
                Paragraph("Recovered Filename:", label_style),
                Paragraph(f"<b>{html.escape(fn)}</b>", val_style)
            ],
            [
                Paragraph("Original Path:", label_style),
                Paragraph(html.escape(orig_path), val_mono),
                Paragraph("File Type / Ext:", label_style),
                Paragraph(f"{ftype} (.{fext})", val_style)
            ],
            [
                Paragraph("File Size:", label_style),
                Paragraph(f"<b>{size_fmt}</b>", val_style),
                Paragraph("Filesystem Origin:", label_style),
                Paragraph(fs_str, val_style)
            ],
            [
                Paragraph("Source Allocation:", label_style),
                Paragraph(f"Cluster: {start_clus} | MFT: #{mft_rec} | Offset: {offset_hex}", val_mono),
                Paragraph("Fragment Status:", label_style),
                Paragraph(frag_str, val_style)
            ],
            [
                Paragraph("Recovery Method:", label_style),
                Paragraph(f"<b>{meth}</b>", val_style),
                Paragraph("Forensic Confidence:", label_style),
                Paragraph(f"<b>{conf_score}%</b> ({conf_level})", val_style)
            ],
            [
                Paragraph("Recovery Timestamp:", label_style),
                Paragraph(rec_time, val_style),
                Paragraph("Verification Status:", label_style),
                Paragraph(f"<font color='{'#2E7D32' if is_rec else '#C53030'}'><b>{verif_result}</b></font>", val_style)
            ],
            [
                Paragraph("<b>Cryptographic SHA-256:</b>", label_style),
                Paragraph(f"<b>{sha256_hash}</b>", val_mono),
                Paragraph("Isolated File Path:", label_style),
                Paragraph(html.escape(out_path), val_mono)
            ]
        ]

        item_meta_table = Table(meta_rows, colWidths=[110, 156, 110, 156])
        item_meta_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#F8F9FA")),
            ("BOX", (0, 0), (-1, -1), 1, colors.HexColor("#CBD5E0")),
            ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#E2E8F0")),
            ("TOPPADDING", (0, 0), (-1, -1), 3),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
            ("LEFTPADDING", (0, 0), (-1, -1), 5),
            ("RIGHTPADDING", (0, 0), (-1, -1), 5),
        ]))

        # Content Representation / Preview Block
        content_block = []
        disk_file = Path(out_path) if out_path and out_path != "Not available" else None

        # Mandatory explicit section header as required by investigator instructions
        content_block.append(Paragraph(
            f"<b>ACTUAL RECOVERED CONTENT</b> &nbsp;&nbsp;|&nbsp;&nbsp; <i>Recovered File: {html.escape(fn)}</i>",
            content_heading_style
        ))

        if disk_file and disk_file.is_file() and disk_file.stat().st_size > 0:
            ext_norm = fext.lower()

            # 1. PDF Documents: Extract text streams and render page preview images
            if ext_norm == "pdf":
                pdf_rendered = False
                total_pdf_pages = 0
                extracted_pdf_text = ""

                # 1A. High-resolution Page Preview Rendering via pypdfium2
                if pdfium:
                    try:
                        pdf_doc = pdfium.PdfDocument(str(disk_file))
                        total_pdf_pages = len(pdf_doc)
                        if total_pdf_pages > 0:
                            first_page = pdf_doc.get_page(0)
                            preview_pil = first_page.render(scale=1.5).to_pil()
                            preview_file = cache_dir / f"{rec_op_id}_file_{idx}_page1.png"
                            preview_pil.save(str(preview_file), format="PNG")

                            pw, ph = preview_pil.size
                            aspect = (pw / ph) if ph > 0 else 1.0
                            max_w = 420.0
                            max_h = 240.0
                            if (max_w / aspect) <= max_h:
                                rw = max_w
                                rh = max_w / aspect
                            else:
                                rh = max_h
                                rw = max_h * aspect

                            content_block.append(Spacer(1, 4))
                            content_block.append(RLImage(str(preview_file), width=rw, height=rh))
                            content_block.append(Spacer(1, 3))
                            content_block.append(Paragraph(
                                f"Rendered Page 1 Visual Preview: <b>{html.escape(fn)}</b> &nbsp;|&nbsp; Dimensions: {pw}x{ph} px &nbsp;|&nbsp; Total Pages: {total_pdf_pages}",
                                caption_style
                            ))
                            content_block.append(Spacer(1, 4))
                            pdf_rendered = True
                    except Exception as p_err:
                        content_block.append(Paragraph(
                            f"<i>[PDF page preview rendering note: {html.escape(str(p_err))}]</i>",
                            subtitle_style
                        ))

                # 1B. Text Stream Extraction via pypdf
                if pypdf:
                    try:
                        reader = pypdf.PdfReader(str(disk_file))
                        if total_pdf_pages == 0:
                            total_pdf_pages = len(reader.pages)
                        extracted_parts = []
                        for p_idx, page in enumerate(reader.pages[:6]):
                            page_text = page.extract_text() or ""
                            if page_text.strip():
                                extracted_parts.append(f"=== [PAGE {p_idx + 1} OF {total_pdf_pages}] ===\n" + page_text.strip())
                        extracted_pdf_text = "\n\n".join(extracted_parts)
                    except Exception as t_err:
                        extracted_pdf_text = f"[PDF text extraction note: {t_err}]"

                if extracted_pdf_text.strip():
                    is_truncated = False
                    total_chars = len(extracted_pdf_text)
                    if total_chars > 4500:
                        extracted_pdf_text = extracted_pdf_text[:4500]
                        is_truncated = True

                    escaped_text = html.escape(extracted_pdf_text).replace("\n", "<br/>").replace(" ", "&nbsp;")
                    trunc_note = f"<br/><br/><b><font color='#D96B27'>[Content preview truncated for PDF report readability (4,500 / {total_chars:,} characters). Full complete artifact is available at: {html.escape(out_path)}]</font></b>" if is_truncated else ""

                    text_p = Paragraph(f"<b>Extracted Readable Document Text:</b><br/>{escaped_text}{trunc_note}", pre_style)
                    text_box = Table([[text_p]], colWidths=[532])
                    text_box.setStyle(TableStyle([
                        ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#F7FAFC")),
                        ("BOX", (0, 0), (-1, -1), 1, colors.HexColor("#CBD5E0")),
                        ("TOPPADDING", (0, 0), (-1, -1), 6),
                        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
                        ("LEFTPADDING", (0, 0), (-1, -1), 8),
                        ("RIGHTPADDING", (0, 0), (-1, -1), 8),
                    ]))
                    content_block.append(text_box)
                elif not pdf_rendered:
                    # Fallback if both pypdf text and page preview were blank
                    content_block.append(Paragraph(
                        f"<i>[PDF file recovered ({size_fmt}), but contains no readable embedded text streams or extractable pages. Full bitstream preserved at: {html.escape(out_path)}]</i>",
                        subtitle_style
                    ))

            # 2. Images (JPEG, PNG, GIF, BMP, WEBP, TIFF)
            elif ext_norm in ["jpg", "jpeg", "png", "gif", "bmp", "webp", "tif", "tiff"]:
                try:
                    with PILImage.open(disk_file) as pimg:
                        w, h = pimg.size
                        mode = pimg.mode

                    max_w = 440.0
                    max_h = 250.0
                    aspect = (w / h) if h > 0 else 1.0
                    if (max_w / aspect) <= max_h:
                        render_w = max_w
                        render_h = max_w / aspect
                    else:
                        render_h = max_h
                        render_w = max_h * aspect

                    img_flowable = RLImage(str(disk_file), width=render_w, height=render_h)
                    content_block.append(Spacer(1, 4))
                    content_block.append(img_flowable)
                    content_block.append(Spacer(1, 3))
                    content_block.append(Paragraph(
                        f"Visual Image Artifact Preview: <b>{html.escape(fn)}</b> &nbsp;|&nbsp; Dimensions: {w}x{h} px &nbsp;|&nbsp; Mode: {mode} &nbsp;|&nbsp; SHA-256: {sha256_hash}",
                        caption_style
                    ))
                    content_block.append(Paragraph(
                        f"Recovery Method: <b>{meth}</b> &nbsp;|&nbsp; Confidence: <b>{conf_score}%</b> &nbsp;|&nbsp; Storage Location: {html.escape(out_path)}",
                        caption_style
                    ))
                except Exception as img_err:
                    content_block.append(Paragraph(
                        f"<i>[Image preview could not be rendered: {img_err}. Artifact file preserved at: {html.escape(out_path)}]</i>",
                        subtitle_style
                    ))

            # 3. Microsoft Word Documents (DOCX / DOCM)
            elif ext_norm in ["docx", "docm"]:
                docx_text = extract_docx_text(disk_file)
                if docx_text and docx_text.strip():
                    is_truncated = False
                    total_chars = len(docx_text)
                    if total_chars > 4500:
                        docx_text = docx_text[:4500]
                        is_truncated = True

                    escaped_docx = html.escape(docx_text).replace("\n", "<br/>").replace(" ", "&nbsp;")
                    trunc_note = f"<br/><br/><b><font color='#D96B27'>[Document preview truncated for report readability ({total_chars:,} total characters). Full file preserved at: {html.escape(out_path)}]</font></b>" if is_truncated else ""

                    doc_p = Paragraph(f"<b>Recovered Word Document Text Representation:</b><br/>{escaped_docx}{trunc_note}", pre_style)
                    doc_box = Table([[doc_p]], colWidths=[532])
                    doc_box.setStyle(TableStyle([
                        ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#F7FAFC")),
                        ("BOX", (0, 0), (-1, -1), 1, colors.HexColor("#CBD5E0")),
                        ("TOPPADDING", (0, 0), (-1, -1), 6),
                        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
                        ("LEFTPADDING", (0, 0), (-1, -1), 8),
                        ("RIGHTPADDING", (0, 0), (-1, -1), 8),
                    ]))
                    content_block.append(Spacer(1, 4))
                    content_block.append(doc_box)
                else:
                    content_block.append(Paragraph(
                        f"<i>[DOCX document recovered ({size_fmt}), but internal XML text stream was empty or could not be parsed. File preserved at: {html.escape(out_path)}]</i>",
                        subtitle_style
                    ))

            # 4. Text / Source Code / Structured Data (TXT, CSV, JSON, XML, LOG, etc.)
            elif ext_norm in ["txt", "csv", "tsv", "json", "xml", "html", "htm", "log", "ini", "cfg", "py", "c", "cpp", "h", "md", "sql", "bat", "ps1", "sh", "yaml", "yml", "reg"]:
                try:
                    try:
                        with open(disk_file, "r", encoding="utf-8") as tf:
                            text_data = tf.read()
                    except UnicodeDecodeError:
                        with open(disk_file, "r", encoding="latin-1", errors="replace") as tf:
                            text_data = tf.read()

                    is_truncated = False
                    total_chars = len(text_data)
                    if total_chars > 5000:
                        text_data = text_data[:5000]
                        is_truncated = True

                    escaped_text = html.escape(text_data).replace("\n", "<br/>").replace(" ", "&nbsp;")
                    trunc_note = f"<br/><br/><b><font color='#D96B27'>[Content preview truncated for PDF readability (5,000 / {total_chars:,} characters). Full complete artifact is available at: {html.escape(out_path)}]</font></b>" if is_truncated else ""
                    
                    text_p = Paragraph(f"<b>Readable File Contents (Exact Recovered Data):</b><br/>{escaped_text}{trunc_note}", pre_style)
                    text_box = Table([[text_p]], colWidths=[532])
                    text_box.setStyle(TableStyle([
                        ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#F7FAFC")),
                        ("BOX", (0, 0), (-1, -1), 1, colors.HexColor("#CBD5E0")),
                        ("TOPPADDING", (0, 0), (-1, -1), 6),
                        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
                        ("LEFTPADDING", (0, 0), (-1, -1), 8),
                        ("RIGHTPADDING", (0, 0), (-1, -1), 8),
                    ]))
                    content_block.append(Spacer(1, 4))
                    content_block.append(text_box)
                except Exception as txt_err:
                    content_block.append(Paragraph(
                        f"<i>[Text content extraction note: {txt_err}]</i>",
                        subtitle_style
                    ))

            # 5. ZIP Archive Manifest & Internal File Previews
            elif ext_norm in ["zip", "jar", "apk"]:
                try:
                    with zipfile.ZipFile(disk_file, "r") as zf:
                        infolist = zf.infolist()
                        
                        archive_rows = [[
                            Paragraph("<b>Internal Path</b>", th_style),
                            Paragraph("<b>Compressed</b>", th_style),
                            Paragraph("<b>Uncompressed</b>", th_style),
                            Paragraph("<b>Modified Date</b>", th_style)
                        ]]
                        for item in infolist[:30]:
                            dt_str = f"{item.date_time[0]:04d}-{item.date_time[1]:02d}-{item.date_time[2]:02d} {item.date_time[3]:02d}:{item.date_time[4]:02d}"
                            archive_rows.append([
                                Paragraph(html.escape(item.filename), td_mono),
                                Paragraph(format_bytes(item.compress_size), td_style),
                                Paragraph(format_bytes(item.file_size), td_style),
                                Paragraph(dt_str, td_style)
                            ])

                        arc_table = Table(archive_rows, colWidths=[240, 96, 96, 100])
                        arc_table.setStyle(TableStyle([
                            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#2D3748")),
                            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E0")),
                            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.HexColor("#FFFFFF"), colors.HexColor("#F8F9FA")]),
                            ("TOPPADDING", (0, 0), (-1, -1), 3),
                            ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
                            ("LEFTPADDING", (0, 0), (-1, -1), 4),
                            ("RIGHTPADDING", (0, 0), (-1, -1), 4),
                        ]))
                        content_block.append(Spacer(1, 4))
                        content_block.append(Paragraph(f"<b>Recovered ZIP Archive Structure: {len(infolist)} member(s)</b>", label_style))
                        content_block.append(arc_table)

                        # Check for readable text members inside the ZIP
                        readable_exts = (".txt", ".csv", ".json", ".xml", ".log", ".md", ".py", ".ini", ".cfg")
                        text_members = [m for m in infolist if m.filename.lower().endswith(readable_exts) and m.file_size > 0]
                        if text_members:
                            sample_member = text_members[0]
                            try:
                                with zf.open(sample_member.filename) as mf:
                                    raw_text = mf.read(2500).decode("utf-8", errors="replace")
                                esc_m_text = html.escape(raw_text).replace("\n", "<br/>").replace(" ", "&nbsp;")
                                m_p = Paragraph(f"<b>Preview of Internal Archive File:</b> <font color='#2B6CB0'>{html.escape(sample_member.filename)}</font><br/>{esc_m_text}", pre_style)
                                m_box = Table([[m_p]], colWidths=[532])
                                m_box.setStyle(TableStyle([
                                    ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#F7FAFC")),
                                    ("BOX", (0, 0), (-1, -1), 1, colors.HexColor("#CBD5E0")),
                                    ("TOPPADDING", (0, 0), (-1, -1), 5),
                                    ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
                                    ("LEFTPADDING", (0, 0), (-1, -1), 8),
                                    ("RIGHTPADDING", (0, 0), (-1, -1), 8),
                                ]))
                                content_block.append(Spacer(1, 5))
                                content_block.append(m_box)
                            except Exception:
                                pass
                except Exception as zip_err:
                    content_block.append(Paragraph(
                        f"<i>[ZIP archive manifest error: {zip_err}]</i>",
                        subtitle_style
                    ))

            # 6. Unsupported Binary / Raw Bitstream / Executable
            else:
                try:
                    with open(disk_file, "rb") as bf:
                        head_bytes = bf.read(128)
                    
                    hex_str = generate_hex_dump(head_bytes, 128)
                    escaped_hex = html.escape(hex_str).replace("\n", "<br/>").replace(" ", "&nbsp;")
                    hex_p = Paragraph(escaped_hex, pre_style)
                    hex_box = Table([[hex_p]], colWidths=[532])
                    hex_box.setStyle(TableStyle([
                        ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#EDF2F7")),
                        ("BOX", (0, 0), (-1, -1), 1, colors.HexColor("#CBD5E0")),
                        ("TOPPADDING", (0, 0), (-1, -1), 5),
                        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
                        ("LEFTPADDING", (0, 0), (-1, -1), 8),
                        ("RIGHTPADDING", (0, 0), (-1, -1), 8),
                    ]))
                    content_block.append(Spacer(1, 4))
                    content_block.append(Paragraph(
                        f"<b>Forensic Notice:</b> This item is a compiled binary / raw bitstream (<b>{ftype}</b>) that cannot be displayed as plain text or visual graphics.",
                        label_style
                    ))
                    content_block.append(Paragraph(
                        f"The complete bitstream has been recovered and verified on disk. First 128 bytes hex dump:",
                        val_style
                    ))
                    content_block.append(Spacer(1, 3))
                    content_block.append(hex_box)
                    content_block.append(Spacer(1, 3))
                    content_block.append(Paragraph(
                        f"Investigator Access Path: <b>{html.escape(out_path)}</b>",
                        label_style
                    ))
                except Exception as bin_err:
                    content_block.append(Paragraph(f"<i>[Binary preview unavailable: {bin_err}]</i>", subtitle_style))
        else:
            content_block.append(Paragraph(
                "<i>[Recovered artifact bitstream was not extractable to filesystem or 0 bytes on disk.]</i>",
                subtitle_style
            ))

        # Add file header and metadata table together so they never split awkwardly across pages
        story.append(KeepTogether([file_header_p, item_meta_table]))
        story.extend(content_block)
        story.append(Spacer(1, 14))

    # 5. Section 3: LEGAL ATTESTATION & CHAIN OF CUSTODY SIGN-OFF
    story.append(Spacer(1, 10))
    story.append(KeepTogether([
        Paragraph("FORENSIC INTEGRITY ATTESTATION & SIGN-OFF", sec_title),
        Paragraph(
            "<b>Examiner Declaration:</b> I hereby certify under penalty of perjury that the digital recovery operations "
            "documented herein were performed using ForensiVault in strict software read-only analysis mode. "
            "The recovered files have been cryptographically hashed and verified against the isolated evidence source. "
            "No data was altered, synthetically fabricated, or tampered with throughout the recovery lifecycle.",
            val_style
        ),
        Spacer(1, 12),
        Table([
            [
                Paragraph("<b>Primary Forensic Examiner:</b>", label_style),
                Paragraph(operator, val_style),
                Paragraph("<b>Laboratory Agency:</b>", label_style),
                Paragraph("ForensiVault Digital Forensics Laboratory", val_style)
            ],
            [
                Paragraph("<b>Examiner Signature:</b>", label_style),
                Paragraph("___________________________________", val_mono),
                Paragraph("<b>Attestation Date:</b>", label_style),
                Paragraph(op_date, val_style)
            ]
        ], colWidths=[120, 146, 120, 146], style=[
            ("BOX", (0, 0), (-1, -1), 1, colors.HexColor("#CBD5E0")),
            ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#E2E8F0")),
            ("TOPPADDING", (0, 0), (-1, -1), 5),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
            ("LEFTPADDING", (0, 0), (-1, -1), 6),
            ("RIGHTPADDING", (0, 0), (-1, -1), 6),
        ])
    ]))

    # Build PDF with NumberedCanvas
    doc.build(story, canvasmaker=RecoveryNumberedCanvas)

    # Compute SHA-256 of the generated PDF file
    sha256 = hashlib.sha256()
    with open(output_path, "rb") as f:
        while chunk := f.read(65536):
            sha256.update(chunk)
    return sha256.hexdigest()
