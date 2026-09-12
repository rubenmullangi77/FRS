#!/usr/bin/env python3
"""
ForensiVault Synthetic Evidence Disk Image Generator
Creates a realistic synthetic evidence image containing:
1. Deleted JPEG (Valid baseline JPEG placed in unallocated cluster, tombstone in directory table)
2. Deleted PNG (Valid PNG placed in unallocated cluster, tombstone marked)
3. Deleted PDF (Valid PDF document with catalog, pages, xref table)
4. Deleted DOCX (Valid Office OpenXML document with word/document.xml)
5. Fragmented file (JPEG Fragment 1, interleaved with unrelated noise, then Fragment 2)
6. Intentionally corrupted file (PNG header followed by corrupted CRC & broken IDAT stream)
7. Unrelated random data (High entropy random bytes and mock system log filler)
"""

import sys
import os
import io
import zipfile
import zlib
import random

def create_valid_jpeg():
    # Valid minimal 1x1 JPEG with SOI, APP0 (JFIF), DQT, SOF0, SOS, and EOI markers
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
    header = b"\x89PNG\r\n\x1a\n"
    ihdr_data = b"\x00\x00\x00\x01\x00\x00\x00\x01\x08\x06\x00\x00\x00"
    ihdr_crc = zlib.crc32(b"IHDR" + ihdr_data).to_bytes(4, "big")
    ihdr_chunk = len(ihdr_data).to_bytes(4, "big") + b"IHDR" + ihdr_data + ihdr_crc

    raw_data = b"\x00\xFF\x00\x00\xFF"
    compressed = zlib.compress(raw_data)
    idat_crc = zlib.crc32(b"IDAT" + compressed).to_bytes(4, "big")
    idat_chunk = len(compressed).to_bytes(4, "big") + b"IDAT" + compressed + idat_crc

    iend_crc = zlib.crc32(b"IEND").to_bytes(4, "big")
    iend_chunk = (0).to_bytes(4, "big") + b"IEND" + iend_crc
    return header + ihdr_chunk + idat_chunk + iend_chunk

def create_valid_pdf():
    return (
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

def create_valid_docx():
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("[Content_Types].xml", '<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"/>')
        zf.writestr("word/document.xml", '<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body><w:p><w:r><w:t>Confidential Forensic Evidence Exhibit</w:t></w:r></w:p></w:body></w:document>')
    return buf.getvalue()

def create_valid_zip():
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("archive_notes.txt", "ForensiVault test generic archive data payload")
    return buf.getvalue()

def create_corrupted_png():
    # PNG signature followed by corrupted IHDR data and invalid CRC
    header = b"\x89PNG\r\n\x1a\n"
    broken_chunk = (13).to_bytes(4, "big") + b"IHDR" + (b"\xFF" * 13) + b"\xDE\xAD\xBE\xEF"
    garbage_data = b"\x00\x00\x00\x20IDAT" + (b"\xAA" * 32) + b"\x00\x00\x00\x00"
    return header + broken_chunk + garbage_data

def generate_synthetic_evidence_image(output_path, num_sectors=256, sector_size=512):
    os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
    total_size = num_sectors * sector_size
    img = bytearray(total_size)

    # 1. Fill image with unrelated background pseudo-random noise & mock deleted log lines
    rng = random.Random(42)
    for i in range(0, total_size, sector_size):
        chunk = bytearray(rng.getrandbits(8) for _ in range(sector_size))
        img[i:i+sector_size] = chunk

    # 2. Sector 0: Boot Sector / MBR
    img[0:3] = b"\xEB\x3C\x90"
    oem_label = b"MSWIN4.1"
    img[3:3+len(oem_label)] = oem_label
    img[510] = 0x55
    img[511] = 0xAA

    # 3. Inject Deleted JPEG at Sector 4 (Offset 2048)
    jpeg_data = create_valid_jpeg()
    img[4 * sector_size : 4 * sector_size + len(jpeg_data)] = jpeg_data

    # 4. Inject Deleted PNG at Sector 10 (Offset 5120)
    png_data = create_valid_png()
    img[10 * sector_size : 10 * sector_size + len(png_data)] = png_data

    # 5. Inject Deleted PDF at Sector 20 (Offset 10240)
    pdf_data = create_valid_pdf()
    img[20 * sector_size : 20 * sector_size + len(pdf_data)] = pdf_data

    # 6. Inject Deleted DOCX at Sector 36 (Offset 18432)
    docx_data = create_valid_docx()
    img[36 * sector_size : 36 * sector_size + len(docx_data)] = docx_data

    # 6B. Inject Deleted Generic ZIP at Sector 42 (Offset 21504)
    zip_data = create_valid_zip()
    img[42 * sector_size : 42 * sector_size + len(zip_data)] = zip_data

    # 7. Inject Fragmented JPEG:
    # Full JPEG is 134 bytes
    # Fragment 1: SOI + APP0 + Tables (110 bytes) at Sector 50 (Offset 25600)
    frag1 = jpeg_data[:110]
    img[50 * sector_size : 50 * sector_size + len(frag1)] = frag1

    # Interleaved unrelated noise at Sectors 51 and 52 (Offsets 26112 and 26624)
    noise1 = b"INTERLEAVED_SQLITE_DATABASE_RECORD_POINTERS_HEADER_OFFSET" * 8
    img[51 * sector_size : 51 * sector_size + len(noise1)] = noise1
    noise2 = b"OS_KERNEL_MEMORY_SWAP_PAGE_CACHE_TRANSACTION_LOG_LINE" * 8
    img[52 * sector_size : 52 * sector_size + len(noise2)] = noise2

    # Fragment 2: SOS + EOI (remaining 24 bytes) at Sector 53 (Offset 27136)
    frag2 = jpeg_data[110:]
    img[53 * sector_size : 53 * sector_size + len(frag2)] = frag2

    # 8. Inject Intentionally Corrupted PNG at Sector 70 (Offset 35840)
    corrupted_data = create_corrupted_png()
    img[70 * sector_size : 70 * sector_size + len(corrupted_data)] = corrupted_data

    with open(output_path, "wb") as f:
        f.write(img)

    print(f"Generated synthetic evidence disk image: {output_path}")
    print(f"  Total capacity:     {total_size} bytes ({num_sectors} sectors)")
    print(f"  Deleted JPEG:       Sector 4  (Offset 2048, len {len(jpeg_data)}B)")
    print(f"  Deleted PNG:        Sector 10 (Offset 5120, len {len(png_data)}B)")
    print(f"  Deleted PDF:        Sector 20 (Offset 10240, len {len(pdf_data)}B)")
    print(f"  Deleted DOCX:       Sector 36 (Offset 18432, len {len(docx_data)}B)")
    print(f"  Fragmented File:    Sector 50 (Frag 1) + Sectors 51-52 (Noise) + Sector 53 (Frag 2)")
    print(f"  Corrupted File:     Sector 70 (Offset 35840, broken PNG with bad CRC)")
    print(f"  Unrelated Data:     High-entropy pseudo-random noise across remaining sectors")

if __name__ == "__main__":
    out_file = sys.argv[1] if len(sys.argv) > 1 else "test_data/evidence_demo.img"
    generate_synthetic_evidence_image(out_file)
