# ForensiVault Pro — Digital Forensics & Data Sanitization Platform
### Smart India Hackathon 2026 (SIH-2026) Project

ForensiVault pairs a high-performance **native C++20 forensic engine** (with 53/53 passed automated tests) with a modern, reactive **React + TypeScript + Vite GUI dashboard**.

---

## 🚀 Quick Start & Launch

To start the full desktop application (API bridge daemon + React frontend):

1. Double-click or run:
   ```cmd
   D:\SIH\run_forensivault.bat
   ```
2. Or start manually from a terminal:
   ```bash
   # Terminal 1: Native C++ API Server (Port 8765)
   .\build\bin\forensivault_server.exe --port 8765

   # Terminal 2: Frontend GUI (Port 5173)
   cd frontend
   npm run dev
   ```
3. Open your web browser at **`http://127.0.0.1:5173`**.

---

## 🏛️ System Architecture

```
                               ┌─────────────────────────────────────────┐
                               │       React + TypeScript Frontend       │
                               │        (Dark Cyber Forensic UI)         │
                               └────────────────────┬────────────────────┘
                                                    │ HTTP / JSON API
                                                    ▼
                               ┌─────────────────────────────────────────┐
                               │   ForensiVault API Bridge Daemon (Py)   │
                               │           backend_server.py             │
                               └────────────────────┬────────────────────┘
                                                    │ Subprocess IPC / CLI
                                                    ▼
┌────────────────────────────────────────────────────────────────────────────────────────┐
│                               ForensiVault C++ Core Engine                             │
│                           (build/bin/forensivault_cli.exe)                             │
├──────────────────────────┬─────────────────────────────┬───────────────────────────────┤
│    Carving & Recovery    │         Sanitization        │      Evidence & Audit         │
│  - Multi-Format Carvers  │   - NIST SP 800-88 Clear    │   - Read-Only Evidence Mounts │
│  - Filesystem Analyzers  │   - DoD 5220.22-M 3-Pass    │   - SHA-256 Custody Baselines │
│  - Fragment Reassembler  │   - SystemProtectionGuard   │   - Blockchained Hash Ledger  │
│  - Explainable Scorer    │   - Entropy Verifier        │   - JSON / HTML / PDF Reports │
└──────────────────────────┴─────────────────────────────┴───────────────────────────────┘
```

---

## 🖥️ Graphical User Interface (9 Navigation Screens)

1. **Executive Dashboard (`/dashboard`)**: Live hardware telemetry, mounted forensic disk images, active case status, and C++ engine test verification (53/53 tests passed).
2. **Evidence Custody & Intake (`/evidence`)**: Case workspace initializer, read-only evidence importer, dual SHA-256 / MD5 hasher, and strict cryptographic immutability verifier.
3. **Filesystem Recovery (`/recovery`)**: Metadata-assisted recovery for FAT32, exFAT, and NTFS volumes, directory parsing, and deleted cluster candidate inspection.
4. **Signature Carving (`/carving`)**: Deep magic byte scanner, real-time stage progress, explainable confidence scoring (0–100%), and conservative fragment reconstruction.
5. **Secure File Eraser (`/file_eraser`)**: Single file / directory purge with NIST 800-88 and DoD patterns, hardware limitation disclosures, and `SystemProtectionGuard` blocking Windows system paths.
6. **Drive Sanitization (`/drive_sanitization`)**: Whole disk image purge, pre/post cryptographic SHA-256 zero-entropy verification, and explicit confirmation interlock.
7. **Forensic Reports (`/reports`)**: Comprehensive court-admissible dossiers exported to JSON, interactive HTML, and vector PDF formats.
8. **Cryptographic Audit Journal (`/audit_logs`)**: Immutable event ledger with SHA-256 hash pointer chaining for tamper-evident tracking.
9. **System Settings & Diagnostics (`/settings`)**: Engine diagnostic self-check, environment telemetry, and SIH project metadata.

---

## 🧪 C++ Native Core Verification

The underlying C++ forensic core remains untouched and 100% verified:
```bash
.\build\bin\forensivault_tests.exe
# Output: Test Summary: 53 total | 53 passed | 0 failed
```
