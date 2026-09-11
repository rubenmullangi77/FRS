# ForensiVault: Forensic Data Recovery & Secure Sanitization Platform

ForensiVault is an enterprise-grade cybersecurity and digital forensics desktop platform built for the Smart India Hackathon. It provides high-assurance digital evidence recovery and standards-compliant data sanitization on Windows systems.

---

## Key Capabilities

### 1. Advanced File Carving & Recovery (Non-Destructive)
- **Physical Sector & Disk Image Carving**: Analyzes raw `.dd`, `.img`, and disk images in strict read-only mode (emulated hardware write-blocker).
- **Deep Signature Scanner**: Fast Boyer-Moore search for file headers, footers, and internal markers (JPEG, PNG, PDF, ZIP/Office, MP4, SQLite, etc.).
- **Structural Integrity Validation**: Parses internal file structures (EXIF, IHDR/IDAT chunk CRC32, PDF xref tables, ZIP Central Directory) before declaring recovery validity.
- **Bi-Fragment Reconstruction**: Reassembles fragmented clusters using entropy differentials and boundary analysis.
- **Multi-Factor Confidence Scoring**: Calculates a transparent 0-100% forensic recovery confidence rating with human-readable rationale.

### 2. Secure File & Folder Eraser (Destructive - Safeguarded)
- **Standards-Compliant Overwrites**: Supports NIST SP 800-88 Rev 1 (Clear & Purge), DoD 5220.22-M (3-pass & 7-pass), Random, and Zero-fill algorithms.
- **Metadata Scrubbing**: Randomizes file names, resets timestamps to epoch, and truncates file lengths to zero before unlinking.
- **Slack Space Erasure**: Sanitizes residual cluster slack space without harming active allocations.

### 3. Secure Drive Sanitization (Destructive - Safeguarded)
- **Drive-Level Wipe**: Overwrites entire raw images or designated non-system storage devices.
- **Fail-Safe Safety Interlocks**: Hardcoded protection preventing any operation on the Windows system drive (`C:`, Boot drive, OS partition). Requires explicit multi-step confirmation.
- **Cryptographic Post-Wipe Verification**: Rescans wiped sectors, confirms 100% entropy depletion or zero-byte fill, and generates a SHA-256 verification hash.

### 4. Forensic Audit Logging & Evidence Reporting
- **Tamper-Evident SHA-256 Journal**: Chained cryptographic log records every sector scan, carving event, and sanitization pass.
- **Automated Report Generation**: Exports formal forensic acquisition reports and sanitization certificates in structured JSON and HTML format.

---

## Technical Architecture

```
ForensiVault/
├── backend/                # C++17/20 High-performance modular core engine
│   ├── include/forensivault/
│   │   ├── common/         # Types, crypto hashing (SHA256, MD5, CRC32), logging
│   │   ├── core/           # Disk image readers and sector I/O
│   │   ├── carving/        # Signatures, carver, validator, fragment reconstructor
│   │   ├── recovery/       # Recovery manager and candidate inventory
│   │   ├── sanitization/   # Secure eraser, drive sanitizer, verification engine
│   │   ├── audit/          # Cryptographically chained tamper-evident audit logger
│   │   └── reporting/      # Forensic reports & sanitization certificates
│   └── src/                # Module implementations and CLI daemon
├── frontend/               # React + TypeScript + Tailwind CSS desktop UI
├── tests/                  # Automated unit and integration test framework
└── samples/                # Synthetic test disk images (.dd/.img)
```

---

## Building & Testing

### Prerequisites
- **CMake** (v3.20+)
- **GCC / Clang / MSVC** (C++17 or newer)
- **Ninja** or **Make**
- **Node.js** (v18+) & **npm**

### Building C++ Core Engine & Tests
```powershell
cmake -B build -G Ninja -DCMAKE_CXX_COMPILER=g++ -DCMAKE_BUILD_TYPE=Debug
cmake --build build
```

### Running Automated Forensic Tests
```powershell
.\build\bin\forensivault_tests.exe
```

### Running CLI
```powershell
.\build\bin\forensivault_cli.exe --help
```

---

## Forensic Safety Guarantee
- **Never modifies a live system disk**: System volume detection prevents destructive targeting.
- **Non-destructive recovery**: Carving is performed strictly read-only.
- **Realistic forensics**: Truly overwritten sectors are marked unrecoverable; claims of recovering overwritten data are mathematically rejected.
