#!/usr/bin/env python3
"""
ForensiVault Synthetic Disk Image Generator with Valid Embedded Files
Generates an uncorrupted forensic disk image containing valid files:
- JPEG
- PNG
- PDF
- ZIP
- DOCX (ZIP containing word/document.xml)
- MP3 (ID3v2)
- MP4 (ftyp)
Used for automated carving validation.
"""

import sys
import os
import zipfile
import io

def create_valid_jpeg():
    # Minimal valid JPEG with SOI, APP0 (JFIF), DQT, SOF0, SOS, EOI
    # Or a standard 1x1 pixel baseline JPEG
    return bytes([
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

def create_valid_png():
    # Minimal 1x1 valid PNG
    import zlib
    header = b"\x89PNG\r\n\x1a\n"
    # IHDR: 1x1, 8-bit RGBA, deflate, filter 0, no interlace
    ihdr_data = b"\x00\x00\x00\x01\x00\x00\x00\x01\x08\x06\x00\x00\x00"
    ihdr_crc = zlib.crc32(b"IHDR" + ihdr_data).to_bytes(4, "big")
    ihdr_chunk = len(ihdr_data).to_bytes(4, "big") + b"IHDR" + ihdr_data + ihdr_crc
    
    # IDAT: 1 pixel (filter byte 0 + RGBA: 255, 0, 0, 255)
    raw_data = b"\x00\xFF\x00\x00\xFF"
    compressed = zlib.compress(raw_data)
    idat_crc = zlib.crc32(b"IDAT" + compressed).to_bytes(4, "big")
    idat_chunk = len(compressed).to_bytes(4, "big") + b"IDAT" + compressed + idat_crc

    # IEND
    iend_crc = zlib.crc32(b"IEND").to_bytes(4, "big")
    iend_chunk = (0).to_bytes(4, "big") + b"IEND" + iend_crc

    return header + ihdr_chunk + idat_chunk + iend_chunk

def create_valid_pdf():
    # Valid minimal PDF document
    pdf = (
        b"%PDF-1.4\n"
        b"1 0 obj << /Type /Catalog /Pages 2 0 R >> endobj\n"
        b"2 0 obj << /Type /Pages /Kids [3 0 R] /Count 1 >> endobj\n"
        b"3 0 obj << /Type /Page /Parent 2 0 R /MediaBox [0 0 300 144] >> endobj\n"
        b"xref\n"
        b"0 4\n"
        b"0000000000 65535 f \n"
        b"0000000010 00000 n \n"
        b"0000000060 00000 n \n"
        b"0000000117 00000 n \n"
        b"trailer << /Size 4 /Root 1 0 R >>\n"
        b"startxref\n"
        b"190\n"
        b"%%EOF\n"
    )
    return pdf

def create_valid_zip():
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("evidence_log.txt", "ForensiVault Carving Evidence Archive")
    return buf.getvalue()

def create_valid_docx():
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("[Content_Types].xml", '<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"/>')
        zf.writestr("word/document.xml", '<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body><w:p><w:r><w:t>ForensiVault Carved Word Document</w:t></w:r></w:p></w:body></w:document>')
    return buf.getvalue()

def create_valid_mp3():
    # ID3v2.3 tag header (10 bytes) + frame + dummy payload
    # Header: "ID3", ver 3.0, flags 0, tag size 10 (syncsafe: 00 00 00 0A)
    id3 = b"ID3\x03\x00\x00\x00\x00\x00\x0A" + (b"\x00" * 10)
    # Followed by MPEG sync frame: FF FB 90 64
    mp3_frame = b"\xFF\xFB\x90\x64" + (b"\x55" * 128)
    return id3 + mp3_frame

def create_valid_mp4():
    # Minimal MP4 'ftyp' box + 'moov' box
    ftyp_data = b"isom\x00\x00\x02\x00isomiso2mp41"
    ftyp_box = (len(ftyp_data) + 8).to_bytes(4, "big") + b"ftyp" + ftyp_data
    moov_box = (8).to_bytes(4, "big") + b"moov"
    return ftyp_box + moov_box

def generate_carving_evidence_image(output_path, num_sectors=128, sector_size=512):
    os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
    total_size = num_sectors * sector_size
    image = bytearray(total_size)

    # Sector 0: MBR
    image[0:3] = b"\xEB\x3C\x90"
    mbr_msg = b"ForensiVault Forensic Multi-File Image"
    image[3:3+len(mbr_msg)] = mbr_msg
    image[510] = 0x55
    image[511] = 0xAA

    # Inject files at specific sectors:
    files = [
        (2, create_valid_jpeg(), "JPEG"),
        (6, create_valid_png(), "PNG"),
        (12, create_valid_pdf(), "PDF"),
        (20, create_valid_zip(), "ZIP"),
        (30, create_valid_docx(), "DOCX"),
        (45, create_valid_mp3(), "MP3"),
        (60, create_valid_mp4(), "MP4")
    ]

    for sector, data, label in files:
        offset = sector * sector_size
        image[offset : offset + len(data)] = data
        print(f"Placed {label} at sector {sector} (offset {offset}, length {len(data)} bytes)")

    with open(output_path, "wb") as f:
        f.write(image)

    print(f"\nGenerated evidence image: {output_path} ({total_size} bytes, {num_sectors} sectors)")

if __name__ == "__main__":
    out = "test_data/carving_evidence.img" if len(sys.argv) < 2 else sys.argv[1]
    generate_carving_evidence_image(out)
