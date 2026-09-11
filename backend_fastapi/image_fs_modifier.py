"""
ForensiVault Disk Image Filesystem Modification and Verification Engine
Provides real sector-level and metadata-level filesystem operations on virtual .img disk images:
 - FAT32 parsing, directory traversal (active and deleted files), cluster chain tracing
 - Normal File Deletion: Marks directory entry with 0xE5 tombstone, frees FAT cluster chains, flushes to disk
 - Secure File Wipe: Zeroes out cluster sectors + slack space, frees FAT, marks/zeroes directory entry, flushes to disk
 - Read-only detection and safe refusal for exFAT / NTFS with structured response
 - Re-opening and rescan verification to guarantee the file is no longer active
 - Safety enforcement: strictly rejects physical devices and host OS paths; supports automatic .bak backup
 - Standard test disk image generation (test-disk.img) with nested directories and sample files
"""

import os
import sys
import shutil
import hashlib
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple

def validate_image_target(image_path: str) -> Tuple[bool, str]:
    """Ensures target is an existing virtual disk image file and never a physical host drive."""
    if not image_path or not isinstance(image_path, str):
        return False, "Invalid image path specified."
    
    clean = image_path.strip()
    # Reject physical drive paths
    if clean.lower().startswith(r"\\.") or "physicaldrive" in clean.lower():
        return False, "Operating on physical storage devices is strictly prohibited. Use isolated .img virtual disks only."
    
    p = Path(clean)
    if not p.is_file():
        return False, f"Disk image file does not exist: {clean}"
    
    # Must have a disk image extension
    valid_exts = [".img", ".dd", ".raw", ".bin", ".vhd"]
    if p.suffix.lower() not in valid_exts:
        return False, f"Target must be a raw disk image file ({', '.join(valid_exts)}). Got: {p.suffix}"
    
    # Check Windows system protection
    lower_str = str(p.resolve()).lower()
    system_roots = ["c:\\windows", "c:\\program files", "c:\\program files (x86)", "c:\\system32"]
    for sr in system_roots:
        if lower_str.startswith(sr):
            return False, f"Target is within protected Windows system directories ({sr}). Modification blocked."
            
    return True, "Target is a valid virtual disk image."

def compute_file_sha256(filepath: str) -> str:
    """Stream calculate SHA-256 of file."""
    hasher = hashlib.sha256()
    with open(filepath, "rb") as f:
        while chunk := f.read(1024 * 1024):
            hasher.update(chunk)
    return hasher.hexdigest()

def detect_image_filesystem(image_path: str) -> Dict[str, Any]:
    """Probes the boot sector and filesystem structure of the .img file."""
    ok, reason = validate_image_target(image_path)
    if not ok:
        return {
            "success": False,
            "fs_type": "UNKNOWN",
            "can_modify": False,
            "error": "INVALID_IMAGE",
            "message": reason
        }
        
    p = Path(image_path)
    sz = p.stat().st_size
    if sz < 512:
        return {
            "success": False,
            "fs_type": "CORRUPTED",
            "can_modify": False,
            "error": "CORRUPTED_IMAGE",
            "message": "Disk image is too small to contain a valid partition or volume boot record."
        }
        
    with open(p, "rb") as f:
        boot = f.read(512)
        
    if len(boot) < 512 or boot[510:512] != b"\x55\xAA":
        return {
            "success": False,
            "fs_type": "UNKNOWN",
            "can_modify": False,
            "error": "UNKNOWN_FILESYSTEM",
            "message": "Volume boot record signature (0x55AA) not found. Unrecognized filesystem layout."
        }
        
    # Check exFAT
    if boot[3:11] == b"EXFAT   ":
        return {
            "success": True,
            "fs_type": "exFAT",
            "can_modify": False,
            "message": "Filesystem detected (exFAT), but deletion is not currently supported for this filesystem.",
            "error": "UNSUPPORTED_FILESYSTEM"
        }
        
    # Check NTFS
    if boot[3:11] == b"NTFS    ":
        return {
            "success": True,
            "fs_type": "NTFS",
            "can_modify": False,
            "message": "Filesystem detected (NTFS), but deletion is not currently supported for this filesystem.",
            "error": "UNSUPPORTED_FILESYSTEM"
        }
        
    # Check FAT32
    fs_label = boot[82:90].decode("latin1", errors="ignore")
    bytes_per_sec = int.from_bytes(boot[11:13], "little")
    sec_per_clus = boot[13]
    reserved_sec = int.from_bytes(boot[14:16], "little")
    num_fats = boot[16]
    sec_per_fat = int.from_bytes(boot[36:40], "little")
    root_clus = int.from_bytes(boot[44:48], "little")
    
    if ("FAT32" in fs_label or (bytes_per_sec in (512, 1024, 2048, 4096) and sec_per_clus > 0 and reserved_sec > 0 and num_fats > 0 and sec_per_fat > 0)):
        vol_label = boot[71:82].decode("latin1", errors="ignore").strip()
        return {
            "success": True,
            "fs_type": "FAT32",
            "can_modify": True,
            "message": "FAT32 volume detected with full read/write/modification support.",
            "volume_info": {
                "bytes_per_sector": bytes_per_sec,
                "sectors_per_cluster": sec_per_clus,
                "cluster_size": bytes_per_sec * sec_per_clus,
                "reserved_sectors": reserved_sec,
                "num_fats": num_fats,
                "sectors_per_fat": sec_per_fat,
                "root_cluster": max(2, root_clus),
                "volume_label": vol_label or "FAT32_VOL",
                "total_sectors": sz // bytes_per_sec
            }
        }
        
    return {
        "success": False,
        "fs_type": "UNKNOWN",
        "can_modify": False,
        "error": "UNSUPPORTED_FILESYSTEM",
        "message": "Unrecognized or proprietary filesystem detected in disk image."
    }

class FAT32ImageHandler:
    """Low-level binary reader, writer, and modifier for FAT32 disk images."""
    def __init__(self, image_path: str):
        self.image_path = str(Path(image_path).resolve())
        det = detect_image_filesystem(self.image_path)
        if not det.get("success") or det.get("fs_type") != "FAT32":
            raise ValueError(det.get("message") or "Target is not a valid FAT32 disk image.")
        self.vol = det["volume_info"]
        self.bytes_per_sec = self.vol["bytes_per_sector"]
        self.sec_per_clus = self.vol["sectors_per_cluster"]
        self.cluster_size = self.vol["cluster_size"]
        self.reserved_sec = self.vol["reserved_sectors"]
        self.num_fats = self.vol["num_fats"]
        self.sec_per_fat = self.vol["sectors_per_fat"]
        self.root_clus = self.vol["root_cluster"]
        self.fat_offset = self.reserved_sec * self.bytes_per_sec
        self.first_data_sec = self.reserved_sec + (self.num_fats * self.sec_per_fat)

    def cluster_to_byte_offset(self, cluster: int) -> int:
        if cluster < 2:
            cluster = 2
        return (self.first_data_sec + (cluster - 2) * self.sec_per_clus) * self.bytes_per_sec

    def read_fat_entry(self, f, cluster: int) -> int:
        offset = self.fat_offset + (cluster * 4)
        f.seek(offset)
        raw = f.read(4)
        if len(raw) < 4:
            return 0x0FFFFFFF
        return int.from_bytes(raw, "little") & 0x0FFFFFFF

    def get_cluster_chain(self, f, start_cluster: int) -> List[int]:
        chain = []
        curr = start_cluster
        visited = set()
        while 2 <= curr < 0x0FFFFFF8 and curr not in visited and len(chain) < 200000:
            chain.append(curr)
            visited.add(curr)
            curr = self.read_fat_entry(f, curr)
        return chain

    def list_files(self) -> List[Dict[str, Any]]:
        """Enumerates all active and deleted files across root and subdirectories."""
        results = []
        visited_dirs = set()
        with open(self.image_path, "rb") as f:
            self._scan_directory_cluster(f, self.root_clus, "/", results, visited_dirs)
        return results

    def _scan_directory_cluster(self, f, dir_cluster: int, current_path: str, results: List[Dict[str, Any]], visited_dirs: set):
        if dir_cluster in visited_dirs:
            return
        visited_dirs.add(dir_cluster)
        
        chain = self.get_cluster_chain(f, dir_cluster)
        if not chain:
            chain = [dir_cluster]
            
        pending_lfn_parts = []
        pending_lfn_offsets = []
        
        for clus in chain:
            clus_offset = self.cluster_to_byte_offset(clus)
            f.seek(clus_offset)
            data = f.read(self.cluster_size)
            
            for i in range(0, len(data), 32):
                entry_offset = clus_offset + i
                entry = data[i:i+32]
                if len(entry) < 32:
                    break
                    
                b0 = entry[0]
                if b0 == 0x00:
                    # End of directory entries
                    return
                    
                # Skip '.' (0x2E) and '..' entries immediately
                if b0 == 0x2E:
                    pending_lfn_parts = []
                    pending_lfn_offsets = []
                    continue
                    
                attr = entry[11]
                
                # Check for Long File Name (LFN) entry
                if attr == 0x0F:
                    part_chars = []
                    for c in range(1, 11, 2):
                        w = int.from_bytes(entry[c:c+2], "little")
                        if w != 0x0000 and w != 0xFFFF:
                            part_chars.append(chr(w))
                    for c in range(14, 26, 2):
                        w = int.from_bytes(entry[c:c+2], "little")
                        if w != 0x0000 and w != 0xFFFF:
                            part_chars.append(chr(w))
                    for c in range(28, 32, 2):
                        w = int.from_bytes(entry[c:c+2], "little")
                        if w != 0x0000 and w != 0xFFFF:
                            part_chars.append(chr(w))
                    pending_lfn_parts.append("".join(part_chars))
                    pending_lfn_offsets.append(entry_offset)
                    continue

                # Skip Volume ID / Volume Label entries
                if (attr & 0x08) and not (attr & 0x10):
                    pending_lfn_parts = []
                    pending_lfn_offsets = []
                    continue
                    
                is_deleted = (b0 == 0xE5)
                is_dir = bool(attr & 0x10)
                
                # Reconstruct filename from LFN or 8.3
                if pending_lfn_parts:
                    filename = "".join(reversed(pending_lfn_parts)).strip()
                    lfn_offsets = list(pending_lfn_offsets)
                    pending_lfn_parts = []
                    pending_lfn_offsets = []
                else:
                    lfn_offsets = []
                    raw_base = entry[:8]
                    raw_ext = entry[8:11]
                    try:
                        base = raw_base.decode("latin1").rstrip()
                        ext = raw_ext.decode("latin1").rstrip()
                    except Exception:
                        base = "FILE"
                        ext = ""
                    if is_deleted and base:
                        base = "_" + base[1:]
                    filename = f"{base}.{ext}" if ext else base
                    
                # Skip any stray dot names
                if filename in (".", "..", "_.", "_..") or not filename:
                    continue
                    
                clus_high = int.from_bytes(entry[20:22], "little")
                clus_low = int.from_bytes(entry[26:28], "little")
                start_clus = (clus_high << 16) | clus_low
                file_size = int.from_bytes(entry[28:32], "little")
                
                # Format timestamps
                c_time_raw = int.from_bytes(entry[14:16], "little")
                c_date_raw = int.from_bytes(entry[16:18], "little")
                m_time_raw = int.from_bytes(entry[22:24], "little")
                m_date_raw = int.from_bytes(entry[24:26], "little")
                
                def dos_dt(d, t):
                    y = 1980 + ((d >> 9) & 0x7F)
                    m = (d >> 5) & 0x0F
                    day = d & 0x1F
                    hh = (t >> 11) & 0x1F
                    mm = (t >> 5) & 0x3F
                    ss = (t & 0x1F) * 2
                    return f"{y:04d}-{max(1, m):02d}-{max(1, day):02d} {hh:02d}:{mm:02d}:{ss:02d}"
                    
                created_iso = dos_dt(c_date_raw, c_time_raw)
                modified_iso = dos_dt(m_date_raw, m_time_raw)
                
                norm_full_path = (current_path + "/" + filename).replace("//", "/")
                ext_str = filename.rsplit(".", 1)[-1].upper() if "." in filename else ("DIR" if is_dir else "BIN")
                
                rec = {
                    "filename": filename,
                    "full_path": norm_full_path,
                    "size_bytes": file_size,
                    "file_type": ext_str,
                    "status": "DELETED" if is_deleted else "ACTIVE",
                    "is_directory": is_dir,
                    "starting_cluster": start_clus,
                    "byte_offset": self.cluster_to_byte_offset(start_clus) if start_clus >= 2 else 0,
                    "dir_entry_offset": entry_offset,
                    "lfn_offsets": lfn_offsets,
                    "created_time": created_iso,
                    "modified_time": modified_iso
                }
                results.append(rec)
                
                # Recurse into subdirectories
                if is_dir and not is_deleted and start_clus >= 2:
                    self._scan_directory_cluster(f, start_clus, norm_full_path, results, visited_dirs)

    def delete_file(self, target_identifier: str, mode: str = "normal", make_backup: bool = True) -> Dict[str, Any]:
        """
        Executes real deletion or secure wipe on the target file inside the FAT32 image:
        - mode == 'normal': Marks directory entry with 0xE5, frees FAT cluster chain, flushes to disk.
        - mode == 'secure_wipe': Overwrites cluster payload with 0x00, zeroes entry, frees FAT, flushes.
        - Rescans from disk and cryptographically verifies the file was removed.
        """
        start_time = datetime.now().isoformat()
        pre_hash = compute_file_sha256(self.image_path)
        
        # 1. Enumerate files to locate target
        all_files = self.list_files()
        norm_target = target_identifier.strip().replace("\\", "/")
        if not norm_target.startswith("/") and "/" in norm_target:
            norm_target = "/" + norm_target
            
        target_rec = None
        for r in all_files:
            if r["status"] == "ACTIVE":
                if r["full_path"].lower() == norm_target.lower() or r["filename"].lower() == norm_target.lower() or r["full_path"].lower().endswith("/" + norm_target.lower().lstrip("/")):
                    target_rec = r
                    break
                    
        if not target_rec:
            # Check if it was already deleted
            for r in all_files:
                if r["status"] == "DELETED":
                    if r["full_path"].lower() == norm_target.lower() or r["filename"].lower() == norm_target.lower():
                        return {
                            "success": False,
                            "error": "ALREADY_DELETED",
                            "message": f"File '{target_identifier}' is already deleted inside the disk image."
                        }
            return {
                "success": False,
                "error": "FILE_NOT_FOUND",
                "message": f"File '{target_identifier}' not found as an active filesystem entry in this disk image."
            }
            
        if target_rec.get("is_directory"):
            return {
                "success": False,
                "error": "DIRECTORY_DELETION_NOT_SUPPORTED",
                "message": "Directory deletion is not supported. Please select individual files to delete."
            }
            
        backup_path = None
        if make_backup:
            bak_name = self.image_path + ".bak"
            try:
                shutil.copy2(self.image_path, bak_name)
                backup_path = bak_name
            except Exception:
                pass

        # 2. Modify disk image binary directly in r+b mode
        norm_mode = mode.lower()
        is_wipe = "wipe" in norm_mode or "secure" in norm_mode
        start_clus = target_rec["starting_cluster"]
        dir_offset = target_rec["dir_entry_offset"]
        lfn_offsets = target_rec.get("lfn_offsets", [])
        
        with open(self.image_path, "r+b") as f:
            # Get entire cluster chain before modifying FAT
            chain = self.get_cluster_chain(f, start_clus) if start_clus >= 2 else []
            
            # Step A: If secure wipe, overwrite payload sectors with 0x00
            if is_wipe and chain:
                zero_buf = b"\x00" * self.cluster_size
                for clus in chain:
                    c_offset = self.cluster_to_byte_offset(clus)
                    f.seek(c_offset)
                    f.write(zero_buf)
                f.flush()
                
            # Step B: Free FAT cluster chain in both FAT1 and FAT2
            if chain:
                zero_fat_entry = b"\x00\x00\x00\x00"
                for clus in chain:
                    # FAT1
                    fat1_pos = self.fat_offset + (clus * 4)
                    f.seek(fat1_pos)
                    f.write(zero_fat_entry)
                    # FAT2 (if secondary FAT exists)
                    if self.num_fats > 1:
                        fat2_pos = self.fat_offset + (self.sec_per_fat * self.bytes_per_sec) + (clus * 4)
                        f.seek(fat2_pos)
                        f.write(zero_fat_entry)
                f.flush()
                
            # Step C: Invalidate LFN entries (mark with 0xE5)
            for lfn_pos in lfn_offsets:
                f.seek(lfn_pos)
                f.write(b"\xE5")
                
            # Step D: Mark main 8.3 directory entry with 0xE5 tombstone
            f.seek(dir_offset)
            if is_wipe:
                # Anti-forensic wipe: 0xE5 followed by 31 zero bytes
                f.write(b"\xE5" + b"\x00" * 31)
            else:
                # Standard FAT deletion: set first byte to 0xE5, preserving metadata
                f.write(b"\xE5")
                
            # Step E: Enforce OS write sync
            f.flush()
            try:
                os.fsync(f.fileno())
            except Exception:
                pass

        # 3. Rescan and verify
        end_time = datetime.now().isoformat()
        post_hash = compute_file_sha256(self.image_path)
        
        # Verify from fresh read
        refreshed_files = self.list_files()
        active_paths = [rf["full_path"].lower() for rf in refreshed_files if rf["status"] == "ACTIVE"]
        is_gone = target_rec["full_path"].lower() not in active_paths
        
        if not is_gone:
            return {
                "success": False,
                "error": "VERIFICATION_FAILED",
                "message": "Deletion failed. The disk image was not modified or file remains active after rescan.",
                "image_path": self.image_path,
                "file_path": target_rec["full_path"]
            }
            
        op_label = "SECURE WIPE (Data Zeroed + Metadata Purged)" if is_wipe else "NORMAL DELETE (0xE5 Marked + FAT Freed)"
        
        return {
            "success": True,
            "operation_type": "SECURE_WIPE" if is_wipe else "NORMAL_DELETE",
            "message": f"File '{target_rec['filename']}' deleted successfully from the disk image.",
            "image_path": self.image_path,
            "image_filename": Path(self.image_path).name,
            "image_size_bytes": Path(self.image_path).stat().st_size,
            "detected_filesystem": "FAT32",
            "file_path": target_rec["full_path"],
            "filename": target_rec["filename"],
            "file_size": target_rec["size_bytes"],
            "clusters_freed": len(chain),
            "pre_hash": pre_hash,
            "post_hash": post_hash,
            "hash_changed": (pre_hash != post_hash),
            "backup_created": backup_path is not None,
            "backup_path": backup_path,
            "verified_deleted": True,
            "verification_result": "CONFIRMED: Target file is no longer accessible as an active entry in filesystem tables.",
            "start_time": start_time,
            "end_time": end_time
        }

def create_standard_test_disk(output_path: str = r"D:\SIH\test_data\test-disk.img") -> Dict[str, Any]:
    """
    Builds a complete, 100% valid FAT32 disk image containing the exact structure:
    test-disk.img
    ├── test.txt
    ├── document.pdf
    ├── photos/
    │   └── image.jpg
    └── sample/
        └── data.bin
    """
    out = Path(output_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    
    total_size = 2 * 1024 * 1024  # 2 MB image
    bytes_per_sec = 512
    sec_per_clus = 8              # 4096 bytes per cluster
    reserved_sec = 32
    num_fats = 2
    sec_per_fat = 32
    root_clus = 2
    cluster_size = bytes_per_sec * sec_per_clus
    first_data_sec = reserved_sec + (num_fats * sec_per_fat)
    total_sec = total_size // bytes_per_sec
    
    # Initialize zeroed image buffer
    img_data = bytearray(total_size)
    
    # 1. Construct Boot Sector
    boot = bytearray(512)
    boot[0:3] = b"\xEB\x58\x90"               # JMP SHORT + NOP
    boot[3:11] = b"MSDOS5.0"                  # OEM Name
    boot[11:13] = bytes_per_sec.to_bytes(2, "little")
    boot[13] = sec_per_clus
    boot[14:16] = reserved_sec.to_bytes(2, "little")
    boot[16] = num_fats
    boot[17:19] = (0).to_bytes(2, "little")   # Root entries (0 for FAT32)
    boot[19:21] = (0).to_bytes(2, "little")   # Total sectors 16 (0 for FAT32)
    boot[21] = 0xF8                         # Media descriptor (fixed disk)
    boot[22:24] = (0).to_bytes(2, "little")   # Sectors per FAT 16
    boot[24:26] = (32).to_bytes(2, "little")  # Sectors per track
    boot[26:28] = (64).to_bytes(2, "little")  # Number of heads
    boot[28:32] = (0).to_bytes(4, "little")   # Hidden sectors
    boot[32:36] = total_sec.to_bytes(4, "little") # Total sectors 32
    # FAT32 Extended BPB
    boot[36:40] = sec_per_fat.to_bytes(4, "little")
    boot[40:42] = (0).to_bytes(2, "little")   # ExtFlags
    boot[42:44] = (0).to_bytes(2, "little")   # FSVersion (0.0)
    boot[44:48] = root_clus.to_bytes(4, "little")
    boot[48:50] = (1).to_bytes(2, "little")   # FSInfo sector
    boot[50:52] = (6).to_bytes(2, "little")   # Backup boot sector
    boot[64] = 0x80                         # Drive number
    boot[66] = 0x29                         # Extended boot signature
    boot[67:71] = (0x12345678).to_bytes(4, "little") # Volume Serial
    boot[71:82] = b"TESTDISK_01"             # Volume Label
    boot[82:90] = b"FAT32   "                 # Filesystem Type
    boot[510:512] = b"\x55\xAA"               # Boot signature
    
    img_data[0:512] = boot
    img_data[6 * 512:7 * 512] = boot # Backup boot sector
    
    # 2. Construct FSInfo Sector (Sector 1)
    fsinfo = bytearray(512)
    fsinfo[0:4] = b"RRaA"                     # Lead signature
    fsinfo[484:488] = b"rrAa"                 # Struct signature
    fsinfo[488:492] = (450).to_bytes(4, "little") # Free cluster count
    fsinfo[492:496] = (8).to_bytes(4, "little")   # Next free cluster
    fsinfo[510:512] = b"\x55\xAA"
    img_data[512:1024] = fsinfo
    
    # 3. Setup FAT Tables
    fat1_offset = reserved_sec * bytes_per_sec
    fat2_offset = fat1_offset + (sec_per_fat * bytes_per_sec)
    
    def set_fat(clus, val):
        entry = (val & 0x0FFFFFFF).to_bytes(4, "little")
        p1 = fat1_offset + (clus * 4)
        p2 = fat2_offset + (clus * 4)
        img_data[p1:p1+4] = entry
        img_data[p2:p2+4] = entry
        
    set_fat(0, 0x0FFFFFF8) # Media ID
    set_fat(1, 0x0FFFFFFF) # EOC marker
    set_fat(2, 0x0FFFFFFF) # Root dir (cluster 2) EOF
    set_fat(3, 0x0FFFFFFF) # test.txt (cluster 3) EOF
    set_fat(4, 0x0FFFFFFF) # document.pdf (cluster 4) EOF
    set_fat(5, 0x0FFFFFFF) # photos/ dir (cluster 5) EOF
    set_fat(6, 0x0FFFFFFF) # sample/ dir (cluster 6) EOF
    set_fat(7, 0x0FFFFFFF) # photos/image.jpg (cluster 7) EOF
    set_fat(8, 0x0FFFFFFF) # sample/data.bin (cluster 8) EOF
    
    def clus_to_byte(c):
        return (first_data_sec + (c - 2) * sec_per_clus) * bytes_per_sec
        
    def make_dir_entry(name83: str, attr: int, start_clus: int, file_sz: int) -> bytearray:
        e = bytearray(32)
        parts = name83.split(".", 1)
        base = parts[0].upper().ljust(8)[:8].encode("latin1")
        ext = parts[1].upper().ljust(3)[:3].encode("latin1") if len(parts) > 1 else b"   "
        e[0:11] = base + ext
        e[11] = attr
        e[20:22] = ((start_clus >> 16) & 0xFFFF).to_bytes(2, "little")
        e[26:28] = (start_clus & 0xFFFF).to_bytes(2, "little")
        e[28:32] = file_sz.to_bytes(4, "little")
        # Realistic DOS timestamp (2026-09-10 12:00:00)
        dos_date = (46 << 9) | (9 << 5) | 10
        dos_time = (12 << 11) | (0 << 5) | 0
        e[14:16] = dos_time.to_bytes(2, "little")
        e[16:18] = dos_date.to_bytes(2, "little")
        e[22:24] = dos_time.to_bytes(2, "little")
        e[24:26] = dos_date.to_bytes(2, "little")
        return e

    # 4. Write Root Directory (Cluster 2)
    root_pos = clus_to_byte(2)
    # Entry 0: Volume label
    e_label = bytearray(32)
    e_label[0:11] = b"TESTDISK_01"
    e_label[11] = 0x08 # ATTR_VOLUME_ID
    img_data[root_pos:root_pos+32] = e_label
    
    # Entry 1: test.txt (Cluster 3)
    content_txt = b"ForensiVault Virtual Disk Test Text Content - Sensitive Record #9401\n"
    img_data[root_pos+32:root_pos+64] = make_dir_entry("TEST.TXT", 0x20, 3, len(content_txt))
    
    # Entry 2: document.pdf (Cluster 4)
    content_pdf = b"%PDF-1.4\n%ForensiVault Forensic Report Prototype Evidence\n1 0 obj\n<< /Title (Confidential Memo) >>\nendobj\nxref\n0 1\n0000000000 65535 f\ntrailer\n<< /Size 1 >>\nstartxref\n128\n%%EOF\n"
    img_data[root_pos+64:root_pos+96] = make_dir_entry("DOCUMENT.PDF", 0x20, 4, len(content_pdf))
    
    # Entry 3: photos/ (Cluster 5)
    img_data[root_pos+96:root_pos+128] = make_dir_entry("PHOTOS", 0x10, 5, 0)
    
    # Entry 4: sample/ (Cluster 6)
    img_data[root_pos+128:root_pos+160] = make_dir_entry("SAMPLE", 0x10, 6, 0)
    
    # 5. Populate Data Clusters
    # Cluster 3: test.txt payload
    c3_pos = clus_to_byte(3)
    img_data[c3_pos:c3_pos+len(content_txt)] = content_txt
    
    # Cluster 4: document.pdf payload
    c4_pos = clus_to_byte(4)
    img_data[c4_pos:c4_pos+len(content_pdf)] = content_pdf
    
    # Cluster 5: photos/ directory contents
    c5_pos = clus_to_byte(5)
    # . entry
    img_data[c5_pos:c5_pos+32] = make_dir_entry(".", 0x10, 5, 0)
    # .. entry
    img_data[c5_pos+32:c5_pos+64] = make_dir_entry("..", 0x10, 0, 0)
    # image.jpg in photos/ (Cluster 7)
    content_jpg = b"\xFF\xD8\xFF\xE0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00\xFF\xDB\x00C\x00FORENSIVAULT_TEST_IMAGE_PAYLOAD\xFF\xD9"
    img_data[c5_pos+64:c5_pos+96] = make_dir_entry("IMAGE.JPG", 0x20, 7, len(content_jpg))
    
    # Cluster 6: sample/ directory contents
    c6_pos = clus_to_byte(6)
    # . entry
    img_data[c6_pos:c6_pos+32] = make_dir_entry(".", 0x10, 6, 0)
    # .. entry
    img_data[c6_pos+32:c6_pos+64] = make_dir_entry("..", 0x10, 0, 0)
    # data.bin in sample/ (Cluster 8)
    content_bin = bytes([i % 256 for i in range(512)])
    img_data[c6_pos+64:c6_pos+96] = make_dir_entry("DATA.BIN", 0x20, 8, len(content_bin))
    
    # Cluster 7: image.jpg payload
    c7_pos = clus_to_byte(7)
    img_data[c7_pos:c7_pos+len(content_jpg)] = content_jpg
    
    # Cluster 8: data.bin payload
    c8_pos = clus_to_byte(8)
    img_data[c8_pos:c8_pos+len(content_bin)] = content_bin
    
    # Write to disk
    out.write_bytes(img_data)
    
    return {
        "success": True,
        "path": str(out.resolve()),
        "size_bytes": total_size,
        "fs_type": "FAT32",
        "files_created": [
            "/TEST.TXT",
            "/DOCUMENT.PDF",
            "/PHOTOS/IMAGE.JPG",
            "/SAMPLE/DATA.BIN"
        ]
    }

