#!/usr/bin/env python3
"""
ForensiVault Synthetic Disk Image Generator
Generates reproducible forensic disk images (.img / .dd) for testing
carving engines, sector readers, and sanitization validators without
touching physical disks.
"""

import sys
import os

def generate_test_image(output_path, num_sectors=64, sector_size=512):
    os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
    total_size = num_sectors * sector_size
    image = bytearray(total_size)

    # Sector 0: Master Boot Record (MBR) marker simulation
    # Signature at offset 510: 0x55 0xAA
    image[0:3] = b"\xEB\x3C\x90"
    mbr_msg = b"ForensiVault Test Disk Image - SIH 2026"
    image[3:3+len(mbr_msg)] = mbr_msg
    image[510] = 0x55
    image[511] = 0xAA

    # Sector 1: Pattern fill (0xA5)
    image[sector_size : 2 * sector_size] = b"\xA5" * sector_size

    # Sector 2: ASCII forensic metadata block
    meta = b"EVIDENCE_ID: FV-TEST-001 | INVESTIGATOR: ForensiVault Lead | STATUS: ACTIVE"
    image[2 * sector_size : 2 * sector_size + len(meta)] = meta

    # Sector 3: Simulated JPEG header at sector 3
    # JPEG SOI: \xFF\xD8\xFF\xE0, JFIF marker, followed by EOI: \xFF\xD9
    jpeg_header = b"\xFF\xD8\xFF\xE0\x00\x10JFIF\x00\x01\x01\x01\x00`\x00`\x00\x00"
    image[3 * sector_size : 3 * sector_size + len(jpeg_header)] = jpeg_header
    # Put JPEG EOI at offset 3 * sector_size + 200
    image[3 * sector_size + 200 : 3 * sector_size + 202] = b"\xFF\xD9"

    # Sector 4: Zeroed sector (simulating wiped / unallocated slack)
    # Remaining sectors left as 0x00

    with open(output_path, "wb") as f:
        f.write(image)

    print(f"Generated forensic test image: {output_path} ({total_size} bytes, {num_sectors} sectors)")

if __name__ == "__main__":
    out = "test_data/sample_disk.img" if len(sys.argv) < 2 else sys.argv[1]
    sectors = 64 if len(sys.argv) < 3 else int(sys.argv[2])
    generate_test_image(out, sectors)
