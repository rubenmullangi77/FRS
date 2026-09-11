#!/usr/bin/env python3
"""
ForensiVault Synthetic Filesystem Image Generator
Generates minimal, compliant FAT32, exFAT, and NTFS test disk images with:
- Volume boot records and allocation geometry
- Active directory / MFT records
- Deleted file candidates with preserved metadata and clusters
"""

import os
import struct

def generate_fat32_image(filepath):
    total_sectors = 2048  # 1 MB disk
    bytes_per_sec = 512
    sec_per_clus = 8
    clus_size = bytes_per_sec * sec_per_clus
    reserved_sec = 32
    num_fats = 2
    sec_per_fat = 32

    image = bytearray(total_sectors * bytes_per_sec)

    # 1. Boot Sector (Sector 0)
    boot = bytearray(512)
    boot[0:3] = b'\xEB\x58\x90'  # JMP
    boot[3:11] = b'MSDOS5.0'
    struct.pack_into('<H', boot, 11, bytes_per_sec)
    boot[13] = sec_per_clus
    struct.pack_into('<H', boot, 14, reserved_sec)
    boot[16] = num_fats
    struct.pack_into('<H', boot, 19, 0)  # 0 for FAT32
    boot[21] = 0xF8  # Fixed disk
    struct.pack_into('<H', boot, 22, 0)
    struct.pack_into('<I', boot, 32, total_sectors)
    struct.pack_into('<I', boot, 36, sec_per_fat)
    struct.pack_into('<I', boot, 44, 2)  # Root cluster = 2
    struct.pack_into('<H', boot, 48, 1)  # FSInfo sector
    struct.pack_into('<I', boot, 67, 0x1234ABCD)  # Serial number
    boot[71:82] = b'FORENSIVLT '  # Volume label
    boot[82:90] = b'FAT32   '
    boot[510:512] = b'\x55\xAA'
    image[0:512] = boot

    # 2. FAT Tables (Sectors 32 and 64)
    first_data_sec = reserved_sec + (num_fats * sec_per_fat)  # 32 + 64 = 96
    for f in range(num_fats):
        fat_offset = (reserved_sec + f * sec_per_fat) * bytes_per_sec
        struct.pack_into('<I', image, fat_offset, 0x0FFFFFF8)       # Cluster 0
        struct.pack_into('<I', image, fat_offset + 4, 0x0FFFFFFF)   # Cluster 1
        struct.pack_into('<I', image, fat_offset + 8, 0x0FFFFFF8)   # Cluster 2 (Root dir EOF)
        struct.pack_into('<I', image, fat_offset + 12, 0x0FFFFFF8)  # Cluster 3 (Active text EOF)
        struct.pack_into('<I', image, fat_offset + 16, 0x0FFFFFF8)  # Cluster 4 (Active JPEG EOF)
        # Cluster 5 (Deleted PNG): Zero in FAT table to simulate typical OS deletion

    def cluster_offset(clus):
        return (first_data_sec + (clus - 2) * sec_per_clus) * bytes_per_sec

    # 3. Root Directory (Cluster 2)
    root_off = cluster_offset(2)

    # Entry 1: Active README.TXT (Cluster 3)
    e1 = bytearray(32)
    e1[0:11] = b'README  TXT'
    e1[11] = 0x20  # Archive
    struct.pack_into('<H', e1, 14, 0x4800)  # Create time
    struct.pack_into('<H', e1, 16, 0x5821)  # Create date
    struct.pack_into('<H', e1, 20, 0)       # Clus high
    struct.pack_into('<H', e1, 26, 3)       # Clus low = 3
    readme_content = b"ForensiVault FAT32 Active File Content.\nForensic analysis intact."
    struct.pack_into('<I', e1, 28, len(readme_content))
    image[root_off:root_off + 32] = e1

    # Entry 2: Active PHOTO.JPG (Cluster 4)
    e2 = bytearray(32)
    e2[0:11] = b'PHOTO   JPG'
    e2[11] = 0x20
    struct.pack_into('<H', e2, 20, 0)
    struct.pack_into('<H', e2, 26, 4)
    # Valid minimal JPEG
    jpeg_content = (
        b'\xFF\xD8\xFF\xE0\x00\x10JFIF\x00\x01\x01\x01\x00\x60\x00\x60\x00\x00'
        b'\xFF\xDB\x00\x43\x00' + b'\x05' * 64 +
        b'\xFF\xDA\x00\x08\x01\x01\x00\x00\x3F\x00' + b'\xAA\xBB\xCC\xDD' +
        b'\xFF\xD9'
    )
    struct.pack_into('<I', e2, 28, len(jpeg_content))
    image[root_off + 32:root_off + 64] = e2

    # Entry 3: Deleted DELETED.PNG (Cluster 5)
    e3 = bytearray(32)
    e3[0] = 0xE5  # Deleted tombstone marker
    e3[1:11] = b'ELETED PNG'
    e3[11] = 0x20
    struct.pack_into('<H', e3, 20, 0)
    struct.pack_into('<H', e3, 26, 5)  # Clus low = 5
    # Valid minimal PNG
    png_content = (
        b'\x89PNG\r\n\x1a\n'
        b'\x00\x00\x00\x0dIHDR\x00\x00\x00\x01\x00\x00\x00\x01\x08\x02\x00\x00\x00\x90wS\xde'
        b'\x00\x00\x00\x0cIDATx\x9cc\xf8\xcf\xc0\x00\x00\x03\x01\x01\x00\xc9\xfe\x92\xef'
        b'\x00\x00\x00\x00IEND\xaeB`\x82'
    )
    struct.pack_into('<I', e3, 28, len(png_content))
    image[root_off + 64:root_off + 96] = e3

    # Write file payloads to respective clusters
    clus3_off = cluster_offset(3)
    image[clus3_off:clus3_off + len(readme_content)] = readme_content

    clus4_off = cluster_offset(4)
    image[clus4_off:clus4_off + len(jpeg_content)] = jpeg_content

    clus5_off = cluster_offset(5)
    image[clus5_off:clus5_off + len(png_content)] = png_content

    with open(filepath, 'wb') as f:
        f.write(image)
    print(f"Generated FAT32 image: {filepath} ({len(image)} bytes)")


def generate_exfat_image(filepath):
    total_sectors = 2048
    bytes_per_sec = 512
    sec_per_clus = 8
    image = bytearray(total_sectors * bytes_per_sec)

    # 1. Main Boot Sector (Sector 0)
    boot = bytearray(512)
    boot[0:3] = b'\xEB\x76\x90'
    boot[3:11] = b'EXFAT   '
    struct.pack_into('<Q', boot, 72, total_sectors)      # VolumeLength
    struct.pack_into('<I', boot, 80, 24)                 # FatOffset (sector 24)
    struct.pack_into('<I', boot, 84, 8)                  # FatLength
    struct.pack_into('<I', boot, 88, 32)                 # ClusterHeapOffset (sector 32)
    struct.pack_into('<I', boot, 92, 252)                # ClusterCount
    struct.pack_into('<I', boot, 96, 2)                  # FirstClusterOfRootDir
    struct.pack_into('<I', boot, 100, 0x87654321)        # VolumeSerialNumber
    boot[108] = 9  # BytesPerSectorShift (2^9 = 512)
    boot[109] = 3  # SectorsPerClusterShift (2^3 = 8)
    boot[110] = 1  # NumberOfFats
    boot[510:512] = b'\x55\xAA'
    image[0:512] = boot

    def exfat_cluster_offset(clus):
        return (32 + (clus - 2) * sec_per_clus) * bytes_per_sec

    # Cluster 2: Root Directory
    root_off = exfat_cluster_offset(2)

    # Set 1: Active File "REPORT.PDF" (Cluster 3)
    pdf_content = (
        b'%PDF-1.4\n1 0 obj<</Type/Catalog/Pages 2 0 R>>endobj\n'
        b'xref\n0 2\n0000000000 65535 f \n'
        b'trailer<</Size 2/Root 1 0 R>>\nstartxref\n50\n%%EOF\n'
    )
    # 1.1 File Directory Entry (0x85)
    e1 = bytearray(32)
    e1[0] = 0x85  # InUse file
    e1[1] = 2     # SecondaryCount (Stream + 1 Name)
    struct.pack_into('<H', e1, 4, 0x20)  # Archive
    image[root_off:root_off + 32] = e1

    # 1.2 Stream Extension Entry (0xC0)
    e2 = bytearray(32)
    e2[0] = 0xC0  # InUse Stream Extension
    e2[1] = 0x01  # AllocationPossible
    e2[3] = 10    # NameLength
    struct.pack_into('<Q', e2, 8, len(pdf_content))   # ValidDataLength
    struct.pack_into('<I', e2, 20, 3)                 # FirstCluster = 3
    struct.pack_into('<Q', e2, 24, len(pdf_content))  # DataLength
    image[root_off + 32:root_off + 64] = e2

    # 1.3 File Name Entry (0xC1)
    e3 = bytearray(32)
    e3[0] = 0xC1  # InUse File Name
    name1_utf16 = "REPORT.PDF".encode('utf-16le')
    e3[2:2 + len(name1_utf16)] = name1_utf16
    image[root_off + 64:root_off + 96] = e3

    # Set 2: Deleted File "SECRET.LOG" (Cluster 4)
    log_content = b"[2026-09-09 22:00:00] CONFIDENTIAL INVESTIGATION LOG ENTRY\nDELETED EVIDENCE FILE."
    # 2.1 File Directory Entry (0x05 = deleted)
    d1 = bytearray(32)
    d1[0] = 0x05  # Deleted bit 7 = 0
    d1[1] = 2     # SecondaryCount
    struct.pack_into('<H', d1, 4, 0x20)
    image[root_off + 96:root_off + 128] = d1

    # 2.2 Stream Extension (0x40 = deleted)
    d2 = bytearray(32)
    d2[0] = 0x40  # Deleted stream
    d2[1] = 0x01
    d2[3] = 10
    struct.pack_into('<Q', d2, 8, len(log_content))
    struct.pack_into('<I', d2, 20, 4)                 # FirstCluster = 4
    struct.pack_into('<Q', d2, 24, len(log_content))
    image[root_off + 128:root_off + 160] = d2

    # 2.3 File Name (0x41 = deleted)
    d3 = bytearray(32)
    d3[0] = 0x41
    name2_utf16 = "SECRET.LOG".encode('utf-16le')
    d3[2:2 + len(name2_utf16)] = name2_utf16
    image[root_off + 160:root_off + 192] = d3

    # Write file contents to clusters
    clus3_off = exfat_cluster_offset(3)
    image[clus3_off:clus3_off + len(pdf_content)] = pdf_content

    clus4_off = exfat_cluster_offset(4)
    image[clus4_off:clus4_off + len(log_content)] = log_content

    with open(filepath, 'wb') as f:
        f.write(image)
    print(f"Generated exFAT image: {filepath} ({len(image)} bytes)")


def generate_ntfs_image(filepath):
    total_sectors = 2048
    bytes_per_sec = 512
    sec_per_clus = 8
    mft_lcn = 4  # Sector 32
    record_size = 1024
    image = bytearray(total_sectors * bytes_per_sec)

    # 1. NTFS Boot Sector
    boot = bytearray(512)
    boot[0:3] = b'\xEB\x52\x90'
    boot[3:11] = b'NTFS    '
    struct.pack_into('<H', boot, 11, bytes_per_sec)
    boot[13] = sec_per_clus
    struct.pack_into('<Q', boot, 40, total_sectors)
    struct.pack_into('<Q', boot, 48, mft_lcn)          # $MFT cluster 4
    struct.pack_into('<Q', boot, 56, mft_lcn + 1)      # $MFTMirr cluster 5
    boot[64] = 0xF6  # -10 -> 2^10 = 1024 bytes per record
    struct.pack_into('<Q', boot, 72, 0x1122334455667788)
    boot[510:512] = b'\x55\xAA'
    image[0:512] = boot

    mft_base_offset = (mft_lcn * sec_per_clus) * bytes_per_sec

    def build_mft_record(filename, content, is_allocated, record_index):
        rec = bytearray(record_size)
        rec[0:4] = b'FILE'
        struct.pack_into('<H', rec, 4, 48)   # Update seq offset
        struct.pack_into('<H', rec, 6, 3)    # Update seq size
        struct.pack_into('<H', rec, 16, 1)   # Sequence number
        struct.pack_into('<H', rec, 20, 56)  # First attribute offset
        struct.pack_into('<H', rec, 22, 1 if is_allocated else 0)  # Flags: 0x01 allocated, 0x00 deleted

        curr = 56
        # Attribute 1: $FILE_NAME (0x30)
        fn_type = 0x30
        fn_utf16 = filename.encode('utf-16le')
        fn_val_len = 66 + len(fn_utf16)
        fn_attr_len = (24 + fn_val_len + 7) & ~7

        struct.pack_into('<I', rec, curr, fn_type)
        struct.pack_into('<I', rec, curr + 4, fn_attr_len)
        rec[curr + 8] = 0  # Resident
        struct.pack_into('<I', rec, curr + 16, fn_val_len)
        struct.pack_into('<H', rec, curr + 20, 24)  # Value offset

        # $FILE_NAME content
        val_off = curr + 24
        struct.pack_into('<Q', rec, val_off + 8, 133000000000000000)   # Creation FILETIME
        struct.pack_into('<Q', rec, val_off + 16, 133000000000000000)  # Alteration FILETIME
        struct.pack_into('<Q', rec, val_off + 40, len(content))         # Allocated size
        struct.pack_into('<Q', rec, val_off + 48, len(content))         # Real size
        rec[val_off + 64] = len(filename)                               # Name length in chars
        rec[val_off + 65] = 1                                           # Win32 namespace
        rec[val_off + 66:val_off + 66 + len(fn_utf16)] = fn_utf16

        curr += fn_attr_len

        # Attribute 2: $DATA (0x80, resident)
        data_type = 0x80
        data_val_len = len(content)
        data_attr_len = (24 + data_val_len + 7) & ~7

        struct.pack_into('<I', rec, curr, data_type)
        struct.pack_into('<I', rec, curr + 4, data_attr_len)
        rec[curr + 8] = 0  # Resident
        struct.pack_into('<I', rec, curr + 16, data_val_len)
        struct.pack_into('<H', rec, curr + 20, 24)
        rec[curr + 24:curr + 24 + data_val_len] = content

        curr += data_attr_len
        struct.pack_into('<I', rec, curr, 0xFFFFFFFF)  # End of attributes
        return rec

    # Record 0-4: System placeholders
    for r in range(5):
        rec = bytearray(record_size)
        rec[0:4] = b'FILE'
        struct.pack_into('<H', rec, 22, 1)  # In-use
        image[mft_base_offset + r * record_size:mft_base_offset + (r + 1) * record_size] = rec

    # Record 5: Active file "CASE_NOTES.TXT"
    notes_content = b"ForensiVault NTFS Forensic Case Notes.\nSuspect activity recorded on volume."
    rec5 = build_mft_record("CASE_NOTES.TXT", notes_content, True, 5)
    image[mft_base_offset + 5 * record_size:mft_base_offset + 6 * record_size] = rec5

    # Record 6: Deleted file "SUSPECT.JPG"
    jpeg_content = (
        b'\xFF\xD8\xFF\xE0\x00\x10JFIF\x00\x01\x01\x01\x00\x60\x00\x60\x00\x00'
        b'\xFF\xDB\x00\x43\x00' + b'\x07' * 64 +
        b'\xFF\xDA\x00\x08\x01\x01\x00\x00\x3F\x00' + b'\x11\x22\x33\x44' +
        b'\xFF\xD9'
    )
    rec6 = build_mft_record("SUSPECT.JPG", jpeg_content, False, 6)  # False = DELETED candidate!
    image[mft_base_offset + 6 * record_size:mft_base_offset + 7 * record_size] = rec6

    with open(filepath, 'wb') as f:
        f.write(image)
    print(f"Generated NTFS image: {filepath} ({len(image)} bytes)")


if __name__ == '__main__':
    os.makedirs('test_data', exist_ok=True)
    generate_fat32_image('test_data/fat32_evidence.img')
    generate_exfat_image('test_data/exfat_evidence.img')
    generate_ntfs_image('test_data/ntfs_evidence.img')
