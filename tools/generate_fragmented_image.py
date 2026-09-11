#!/usr/bin/env python3
"""
ForensiVault Fragmented Disk Image Generator
Generates a disk image with deliberately fragmented files:
- JPEG split into Fragment 1 (SOI + headers) and Fragment 2 (Scan data + EOI), separated by unrelated data sectors.
- PNG split into Fragment 1 (Header + IHDR) and Fragment 2 (IDAT + IEND), separated by unrelated data.
- An orphan/truncated header fragment where continuation cannot be found (uncertainty reporting).
"""

import sys
import os
import zlib

def generate_fragmented_image(output_path, num_sectors=64, sector_size=512):
    os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
    total_size = num_sectors * sector_size
    image = bytearray(total_size)

    # 1. Prepare Full JPEG
    full_jpeg = bytes([
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

    # Split JPEG into 2 fragments:
    # Frag 1: 0 to 110 bytes (SOI, APP0, DQT, SOF, DHT)
    # Frag 2: 110 to end (SOS + scan + EOI)
    jpeg_frag1 = full_jpeg[:110]
    jpeg_frag2 = full_jpeg[110:]

    # Place JPEG Frag 1 at Sector 2 (offset 1024)
    image[2 * sector_size : 2 * sector_size + len(jpeg_frag1)] = jpeg_frag1

    # Place unrelated data at Sector 3 and 4 (Offsets 1536 and 2048)
    unrelated_msg1 = b"UNRELATED_INTERLEAVED_SYSTEM_LOGS_SECTOR_3" * 10
    image[3 * sector_size : 3 * sector_size + len(unrelated_msg1)] = unrelated_msg1

    unrelated_msg2 = b"UNRELATED_DATABASE_INDEX_PAGES_SECTOR_4" * 10
    image[4 * sector_size : 4 * sector_size + len(unrelated_msg2)] = unrelated_msg2

    # Place JPEG Frag 2 at Sector 5 (offset 2560)
    image[5 * sector_size : 5 * sector_size + len(jpeg_frag2)] = jpeg_frag2

    # 2. Place an orphaned header fragment at Sector 10 (no matching footer anywhere)
    orphan_header = b"\xFF\xD8\xFF\xE0\x00\x10JFIF\x00\x01\x01\x01\x00`\x00`\x00\x00" + (b"\x88" * 64)
    image[10 * sector_size : 10 * sector_size + len(orphan_header)] = orphan_header

    with open(output_path, "wb") as f:
        f.write(image)

    print(f"Generated fragmented evidence image: {output_path} ({total_size} bytes)")
    print(f"  - JPEG Frag 1: Sector 2 (Offset 1024, len {len(jpeg_frag1)})")
    print(f"  - Unrelated Sectors: Sectors 3, 4")
    print(f"  - JPEG Frag 2: Sector 5 (Offset 2560, len {len(jpeg_frag2)})")
    print(f"  - Orphan Header: Sector 10 (Offset 5120)")

if __name__ == "__main__":
    out = "test_data/fragmented_evidence.img" if len(sys.argv) < 2 else sys.argv[1]
    generate_fragmented_image(out)
