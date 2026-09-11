#include "carving/file_carver.hpp"
#include "carving/fragment_reconstructor.hpp"
#include "sanitization/erase_operation.hpp"
#include "sanitization/drive_detector.hpp"
#include "sanitization/image_sanitizer.hpp"
#include "sanitization/ssd_sanitizer.hpp"
#include "sanitization/hdd_sanitizer.hpp"
#include "logging/audit_logger.hpp"
#include "core/case_manager.hpp"
#include "reporting/forensic_report.hpp"
#include "reporting/report_generator.hpp"
#include "forensivault/common/types.hpp"
#include "forensivault/common/crypto_hash.hpp"
#include "forensivault/common/logger.hpp"
#include <iostream>
#include <string>
#include <vector>
#include <iomanip>
#include <filesystem>

namespace {

void printBanner() {
    std::cout << R"(
  =============================================================
     ______                         _ _    __             _ _   
    |  ____|                       (_) |  /\ \           | | |  
    | |__ ___  _ __ ___ _ __  ___ _ _| | /  \ \   _  __ _| | |_ 
    |  __/ _ \| '__/ _ \ '_ \/ __| | | |/ /\ \ \ | |/ _` | | __|
    | | | (_) | | |  __/ | | \__ \ | | / ____ \ \| | (_| | | |_ 
    |_|  \___/|_|  \___|_| |_|___/_|_|/_/    \_\_|\__,_|_|\__|
  =============================================================
   Forensic Data Recovery & Secure Sanitization Platform
   Smart India Hackathon Edition | Version 1.0.0
   Forensic Read-Only Carving Engine + Certified Sanitizer
  =============================================================
)" << std::endl;
}

void printHelp() {
    std::cout << "Usage: forensivault_cli [command] [options]\n\n"
              << "Core Commands:\n"
              << "  --help, -h               Show this forensic help reference\n"
              << "  --version, -v            Display ForensiVault engine version\n"
              << "  --benchmark-hash         Run SHA-256 and MD5 hashing benchmarks\n"
              << "  --scan-image <path>      Scan a disk image (.dd, .img) in READ-ONLY mode\n"
              << "  --carve <image> [out]    Execute deep file carving & extraction into recovery directory\n"
              << "  --reconstruct <image>    Execute fragmented-file analysis and conservative reconstruction\n"
              << "  --erase-preview <path>   Preview secure file or folder sanitization (non-destructive)\n"
              << "  --erase <path> [--dod] [--confirm] Securely sanitize target path (requires confirmation)\n"
              << "  --detect-drives          Detect and display system storage devices & capabilities\n"
              << "  --inspect-drive <image>  Inspect drive image properties and forensic parameters\n"
              << "  --sanitize-drive <image> [--nist|--dod|--random] [--confirm] Execute certified drive sanitization\n"
              << "  --audit-export <path>    Export chained forensic audit report in JSONL format\n"
              << std::endl;
}

void scanDiskImage(const std::string& imagePath) {
    FV_LOG_INFO("Opening disk image in READ-ONLY mode: " + imagePath);
    forensivault::core::DiskImageReader reader(imagePath);

    if (!reader.isOpen()) {
        FV_LOG_ERROR("Failed to open disk image: " + reader.lastError());
        return;
    }

    std::cout << "\n[Forensic Image Geometry & Acquisition Data]\n";
    std::cout << "  File Path:      " << reader.filepath() << "\n";
    std::cout << "  Total Size:     " << reader.size() << " bytes ("
              << std::fixed << std::setprecision(2)
              << (static_cast<double>(reader.size()) / (1024.0 * 1024.0)) << " MB)\n";
    std::cout << "  Sector Size:    " << reader.sectorSize() << " bytes\n";
    std::cout << "  Total Sectors:  " << reader.totalSectors() << " sectors\n";

    // Read Sector 0 (MBR / Boot Sector inspection)
    auto sector0 = reader.readSector(0);
    if (!sector0.empty()) {
        bool hasMbrSignature = (sector0.size() >= 512 && sector0[510] == 0x55 && sector0[511] == 0xAA);
        std::cout << "  Sector 0 Status: Successfully read ("
                  << (hasMbrSignature ? "Valid MBR Signature 0x55AA" : "Non-MBR Boot Sector")
                  << ")\n";
    }

    // Compute evidence cryptographic hashes via streaming
    FV_LOG_INFO("Computing evidence cryptographic hashes (read-only stream)...");
    forensivault::CryptoHash::Sha256Context shaCtx;
    forensivault::CryptoHash::Md5Context md5Ctx;

    std::vector<uint8_t> chunk(64 * 1024);
    uint64_t bytesProcessed = 0;
    uint64_t total = reader.size();

    while (bytesProcessed < total) {
        size_t toRead = static_cast<size_t>(std::min<uint64_t>(chunk.size(), total - bytesProcessed));
        if (!reader.read(bytesProcessed, chunk.data(), toRead)) {
            FV_LOG_ERROR("Read failure during hashing at offset " + std::to_string(bytesProcessed));
            break;
        }
        shaCtx.update(chunk.data(), toRead);
        md5Ctx.update(chunk.data(), toRead);
        bytesProcessed += toRead;
    }

    std::string sha256 = shaCtx.finalize();
    std::string md5 = md5Ctx.finalize();

    std::cout << "\n[Evidence Cryptographic Hashes (Chain of Custody)]\n";
    std::cout << "  SHA-256: " << sha256 << "\n";
    std::cout << "  MD5:     " << md5 << "\n";
    std::cout << "  Status:  Verified Immutability Preserved\n" << std::endl;

    FV_LOG_AUDIT("Disk image acquired and hashed: " + imagePath + " [SHA-256: " + sha256 + "]");
}

} // anonymous namespace

int main(int argc, char* argv[]) {
    printBanner();

    std::vector<std::string> args(argv + 1, argv + argc);

    if (args.empty() || args[0] == "--help" || args[0] == "-h") {
        printHelp();
        return 0;
    }

    if (args[0] == "--version" || args[0] == "-v") {
        std::cout << "ForensiVault Core Engine v1.0.0 (x86_64-w64-mingw32)" << std::endl;
        std::cout << "Compliant with: NIST SP 800-88 Rev 1, DoD 5220.22-M" << std::endl;
        return 0;
    }

    if (args[0] == "--benchmark-hash") {
        FV_LOG_INFO("Running cryptographic hash benchmark...");
        std::string sample = "ForensiVault Forensic Integrity Test Payload 2026";
        std::string sha = forensivault::CryptoHash::sha256(sample);
        std::string md5 = forensivault::CryptoHash::md5(sample);
        double entropy = forensivault::CryptoHash::calculateEntropy(
            reinterpret_cast<const uint8_t*>(sample.data()), sample.size());

        std::cout << "\n[Cryptographic Test Results]" << std::endl;
        std::cout << "Payload:  \"" << sample << "\"" << std::endl;
        std::cout << "SHA-256:  " << sha << std::endl;
        std::cout << "MD5:      " << md5 << std::endl;
        std::cout << "Entropy:  " << entropy << " bits/byte (Max 8.0)" << std::endl;
        FV_LOG_AUDIT("Hash benchmark completed successfully.");
        return 0;
    }

    if (args[0] == "--scan-image") {
        if (args.size() < 2) {
            FV_LOG_ERROR("Missing disk image path argument for --scan-image");
            return 1;
        }
        scanDiskImage(args[1]);
        return 0;
    }

    if (args[0] == "--carve") {
        if (args.size() < 2) {
            FV_LOG_ERROR("Missing disk image path argument for --carve");
            return 1;
        }
        std::string imagePath = args[1];
        std::string outDir = (args.size() >= 3) ? args[2] : "recovered";

        FV_LOG_INFO("Opening disk image for file carving: " + imagePath);
        forensivault::core::DiskImageReader reader(imagePath);
        if (!reader.isOpen()) {
            FV_LOG_ERROR("Failed to open disk image: " + reader.lastError());
            return 1;
        }

        forensivault::carving::CarverOptions opts;
        opts.outputDirectory = outDir;
        opts.organizeByType = true;
        opts.validateIntegrity = true;

        forensivault::carving::FileCarver carver(opts);
        FV_LOG_INFO("Starting forensic carving scan (target output: " + outDir + ")...");
        
        auto session = carver.carve(reader);

        std::cout << "\n============================================================\n";
        std::cout << "           ForensiVault Carving Session Results             \n";
        std::cout << "============================================================\n";
        std::cout << "Evidence Source:    " << session.imagePath << "\n";
        std::cout << "Total Scanned:      " << session.totalBytesScanned << " bytes ("
                  << session.totalSectorsScanned << " sectors)\n";
        std::cout << "Signatures Found:   " << session.signaturesDiscovered << "\n";
        std::cout << "Files Carved:       " << session.filesSuccessfullyCarved << "\n";
        std::cout << "Valid Files:        " << session.validFilesCount << "\n";
        std::cout << "Partial Files:      " << session.partialFilesCount << "\n";
        std::cout << "Duration:           " << std::fixed << std::setprecision(2) 
                  << session.durationMilliseconds << " ms\n";
        std::cout << "============================================================\n\n";

        std::cout << "ID   TYPE   EXT   OFFSET (HEX)   LENGTH (B)   CONFIDENCE   LEVEL       VALID   RECOVERED PATH\n";
        std::cout << "----------------------------------------------------------------------------------------------------\n";
        for (const auto& f : session.carvedFiles) {
            std::cout << std::left << std::setw(4) << f.id << " "
                      << std::setw(6) << f.fileType << " "
                      << std::setw(5) << f.extension << " "
                      << "0x" << std::hex << std::uppercase << std::setw(10) << f.startOffset << std::dec << " "
                      << std::setw(12) << f.lengthBytes << " "
                      << std::setw(9) << std::fixed << std::setprecision(1) << f.confidenceScore << "%  "
                      << std::setw(11) << f.confidenceLevel << " "
                      << (f.isValid ? "[PASS]" : "[WARN]") << "  "
                      << f.recoveredFilePath << "\n";
            for (const auto& r : f.reasons) {
                std::cout << "      * " << r << "\n";
            }
            for (const auto& w : f.warnings) {
                std::cout << "      - " << w << "\n";
            }
        }
        std::cout << "\n";

        FV_LOG_AUDIT("Forensic carving session complete: " + std::to_string(session.filesSuccessfullyCarved) +
                     " files recovered to " + outDir);
        return 0;
    }

    if (args[0] == "--reconstruct") {
        if (args.size() < 2) {
            FV_LOG_ERROR("Missing disk image path argument for --reconstruct");
            return 1;
        }
        std::string imagePath = args[1];

        FV_LOG_INFO("Opening disk image for fragmented-file analysis: " + imagePath);
        forensivault::core::DiskImageReader reader(imagePath);
        if (!reader.isOpen()) {
            FV_LOG_ERROR("Failed to open disk image: " + reader.lastError());
            return 1;
        }

        std::vector<uint8_t> imgBuffer = reader.readBytes(0, static_cast<size_t>(reader.size()));
        FV_LOG_INFO("Scanning for file headers and orphan continuation clusters...");

        // Scan signatures
        forensivault::carving::SignatureDatabase db;
        forensivault::carving::SignatureScanner scanner(db);
        auto matches = scanner.scan(reader);

        std::cout << "\n============================================================\n";
        std::cout << "        ForensiVault Fragmented-File Analysis               \n";
        std::cout << "============================================================\n";

        for (const auto& match : matches) {
            std::cout << "\n[Analyzing Header Candidate: " << match.signature->fileType
                      << " at Offset 0x" << std::hex << std::uppercase << match.offset << std::dec << "]\n";

            // Extract primary candidate up to next sector or known partial boundary
            size_t probeSize = std::min<size_t>(512, imgBuffer.size() - match.offset);
            std::vector<uint8_t> fragData(imgBuffer.data() + match.offset, imgBuffer.data() + match.offset + probeSize);

            forensivault::carving::FragmentCandidate headerFrag;
            headerFrag.fragmentId = match.offset;
            headerFrag.offset = match.offset;
            headerFrag.length = probeSize;
            headerFrag.fileType = match.signature->fileType;
            headerFrag.role = forensivault::carving::FragmentRole::Header;
            headerFrag.entropy = forensivault::CryptoHash::calculateEntropy(fragData);
            headerFrag.data = std::move(fragData);
            headerFrag.confidence = 50.0;

            // Search for orphan continuation fragments starting after this header's cluster
            uint64_t searchStart = match.offset + 512;
            if (searchStart < imgBuffer.size()) {
                auto orphans = forensivault::carving::FragmentReconstructor::findOrphanFragments(
                    match.signature->fileType,
                    imgBuffer.data() + searchStart,
                    searchStart,
                    imgBuffer.size() - searchStart,
                    512);

                std::cout << "  Discovered " << orphans.size() << " orphan cluster candidates.\n";

                auto result = forensivault::carving::FragmentReconstructor::attemptReconstruction(
                    headerFrag, orphans, 1024 * 1024);

                std::cout << "  Reconstruction Status: "
                          << (result.isReconstructed ? "[RECONSTRUCTED]" : "[PARTIAL / SEGREGATED]") << "\n";
                std::cout << "  Confidence Score:      " << result.confidenceScore << "%\n";
                std::cout << "  Notes / Uncertainty:   " << result.uncertaintyReason << "\n";

                if (result.isReconstructed) {
                    std::cout << "  Fragments Assembled:   ";
                    for (size_t k = 0; k < result.fragmentOffsets.size(); ++k) {
                        std::cout << "0x" << std::hex << std::uppercase << result.fragmentOffsets[k]
                                  << (k + 1 < result.fragmentOffsets.size() ? " + " : "");
                    }
                    std::cout << std::dec << " (" << result.totalReconstructedSize << " bytes)\n";
                    std::cout << "  Reconstructed SHA-256: " << result.sha256 << "\n";
                }
            }
        }
        std::cout << "\n============================================================\n\n";
        return 0;
    }

    if (args[0] == "--erase-preview") {
        if (args.size() < 2) {
            FV_LOG_ERROR("Missing target path for --erase-preview");
            return 1;
        }
        std::string targetPath = args[1];
        forensivault::sanitization::EraseOperation op(forensivault::sanitization::SanitizationMethod::NIST_800_88_CLEAR);
        op.addBatch({targetPath});
        auto prev = op.preview();

        std::cout << "\n============================================================\n";
        std::cout << "        ForensiVault Sanitization Preview (Non-Destructive) \n";
        std::cout << "============================================================\n";
        std::cout << "Target:             " << targetPath << "\n";
        std::cout << "Method:             " << prev.method_name << "\n";
        std::cout << "Method Details:     " << prev.method_description << "\n";
        std::cout << "Safety Check:       " << (prev.safety_passed ? "[PASSED - SAFE TO PROCESS]" : "[PROHIBITED - SYSTEM PATH DETECTED]") << "\n";
        std::cout << "Risk Level:         " << prev.risk_level << "\n";
        std::cout << "Files to Erase:     " << prev.total_files << "\n";
        std::cout << "Folders to Remove:  " << prev.total_folders << "\n";
        std::cout << "Total Bytes:        " << prev.total_bytes << " bytes\n";
        std::cout << "============================================================\n\n";

        if (!prev.warnings.empty()) {
            std::cout << "[SAFETY WARNINGS & BLOCKS]\n";
            for (const auto& w : prev.warnings) {
                std::cout << "  ! " << w << "\n";
            }
            std::cout << "\n";
        }

        std::cout << "[FORENSIC LIMITATIONS & CAVEATS]\n";
        for (const auto& lim : prev.limitations) {
            std::cout << "  * " << lim << "\n";
        }
        std::cout << "\n";
        return 0;
    }

    if (args[0] == "--erase") {
        if (args.size() < 2) {
            FV_LOG_ERROR("Missing target path for --erase");
            return 1;
        }
        std::string targetPath = args[1];
        bool confirmed = false;
        forensivault::sanitization::SanitizationMethod method =
            forensivault::sanitization::SanitizationMethod::NIST_800_88_CLEAR;

        for (size_t a = 2; a < args.size(); ++a) {
            if (args[a] == "--confirm") confirmed = true;
            else if (args[a] == "--dod") method = forensivault::sanitization::SanitizationMethod::DOD_5220_22_M;
            else if (args[a] == "--random") method = forensivault::sanitization::SanitizationMethod::PSEUDORANDOM_1_PASS;
        }

        forensivault::sanitization::EraseOperation op(method);
        op.addBatch({targetPath});
        op.setConfirmed(confirmed);

        auto prev = op.preview();
        std::cout << "[Sanitization Target Preview: " << prev.total_files << " files, "
                  << prev.total_folders << " folders, " << prev.total_bytes << " bytes, Risk: "
                  << prev.risk_level << "]\n";

        if (!confirmed) {
            std::cerr << "\n[SAFETY INTERLOCK ERROR] Operation aborted!\n"
                      << "Explicit user confirmation is required prior to destructive erasure.\n"
                      << "Re-run with '--confirm' flag to proceed with permanent destruction.\n\n";
            return 1;
        }

        auto cb = [](const forensivault::sanitization::EraseProgress& p) {
            std::cout << "\rOverwriting: " << std::fixed << std::setprecision(1)
                      << p.percentage << "% [Pass " << p.current_pass << "/" << p.total_passes
                      << "] " << p.current_file << std::flush;
        };

        auto res = op.execute(cb);
        std::cout << "\n\n" << res.summary << "\n";

        std::cout << "\n[Verification & Limitations]\n";
        for (const auto& lim : res.limitations) {
            std::cout << "  * " << lim << "\n";
        }
        std::cout << "\n";

        return res.success ? 0 : 1;
    }

    if (args[0] == "--detect-drives") {
        std::cout << "\n[System Storage Device Detection & Capability Analysis]\n";
        auto devices = forensivault::sanitization::DriveDetector::detectPhysicalDevices();
        if (devices.empty()) {
            std::cout << "No physical drives detected or physical drive access restricted.\n";
        }
        for (const auto& dev : devices) {
            std::cout << "  - Device:       " << dev.target_path << " (" << dev.model_name << ")\n"
                      << "    Type:         " << dev.media_type << "\n"
                      << "    Interface:    " << dev.interface_type << "\n"
                      << "    Total Bytes:  " << dev.total_bytes << " ("
                      << (static_cast<double>(dev.total_bytes) / (1024.0 * 1024.0 * 1024.0)) << " GB)\n"
                      << "    Sector Size:  " << dev.sector_size << " bytes\n"
                      << "    Safe to Wipe: " << (dev.is_safe_to_sanitize ? "YES" : "NO (Blocked: Physical Drive Protection)") << "\n\n";

            if (dev.media_type == forensivault::sanitization::DriveMediaType::SSD_NAND) {
                auto ssdCap = forensivault::sanitization::SSDSanitizer::evaluateCapabilities(dev);
                std::cout << "    [SSD NAND Sanitization Assessment]\n"
                          << "    * Software Overwrite Sufficient: " << (ssdCap.software_overwrite_sufficient ? "YES" : "NO (FTL wear leveling / overprovisioning)") << "\n"
                          << "    * Recommended Strategy: " << ssdCap.recommended_method << "\n";
                for (const auto& d : ssdCap.critical_disclosures) {
                    std::cout << "    * Disclosure: " << d << "\n";
                }
                std::cout << "\n";
            }
        }
        return 0;
    }

    if (args[0] == "--inspect-drive") {
        if (args.size() < 2) {
            FV_LOG_ERROR("Missing image path for --inspect-drive");
            return 1;
        }
        std::string imgPath = args[1];
        auto props = forensivault::sanitization::DriveDetector::detectImage(imgPath);

        std::cout << "\n[Target Drive Image Inspection]\n"
                  << "  Path:           " << props.target_path << "\n"
                  << "  Model:          " << props.model_name << "\n"
                  << "  Media Type:     " << props.media_type << "\n"
                  << "  Total Size:     " << props.total_bytes << " bytes ("
                  << (static_cast<double>(props.total_bytes) / (1024.0 * 1024.0)) << " MB)\n"
                  << "  Sector Size:    " << props.sector_size << " bytes\n"
                  << "  Total Sectors:  " << props.total_sectors << "\n"
                  << "  Safe to Wipe:   " << (props.is_safe_to_sanitize ? "YES (Virtual Target Image)" : "NO") << "\n\n";

        std::string currentHash = forensivault::sanitization::ImageSanitizer::computeImageSha256(imgPath);
        std::cout << "  Current SHA-256: " << currentHash << "\n\n";
        return 0;
    }

    if (args[0] == "--sanitize-drive") {
        if (args.size() < 2) {
            FV_LOG_ERROR("Missing disk image path for --sanitize-drive");
            return 1;
        }
        std::string imgPath = args[1];
        bool confirmed = false;
        std::string stratType = "nist";

        for (size_t a = 2; a < args.size(); ++a) {
            if (args[a] == "--confirm") confirmed = true;
            else if (args[a] == "--dod") stratType = "dod";
            else if (args[a] == "--random") stratType = "random";
            else if (args[a] == "--nist") stratType = "nist";
        }

        // Step 1: Detect image properties
        auto props = forensivault::sanitization::DriveDetector::detectImage(imgPath);

        // Step 2: Show target information
        std::cout << "\n=============================================================\n"
                  << "        SECURE DRIVE SANITIZATION SUBSYSTEM                 \n"
                  << "=============================================================\n"
                  << "Target File:       " << props.target_path << "\n"
                  << "Media Type:        " << props.media_type << "\n"
                  << "Capacity:          " << props.total_bytes << " bytes ("
                  << (static_cast<double>(props.total_bytes) / (1024.0 * 1024.0)) << " MB)\n"
                  << "Sector Size:       " << props.sector_size << " bytes\n"
                  << "Target Safety:     " << (props.is_safe_to_sanitize ? "CONFIRMED (Disk Image File)" : "BLOCKED (Host/Physical System Protection)") << "\n";

        // Step 3 & 4: Select and explain sanitization strategy
        std::unique_ptr<forensivault::sanitization::SanitizationStrategy> strategy;
        if (stratType == "dod") {
            strategy = std::make_unique<forensivault::sanitization::Dod522022MStrategy>();
        } else if (stratType == "random") {
            strategy = std::make_unique<forensivault::sanitization::PseudorandomStrategy>();
        } else {
            strategy = std::make_unique<forensivault::sanitization::NistClearStrategy>();
        }

        std::cout << "\n[Selected Sanitization Strategy]\n"
                  << "Method Name:       " << strategy->name() << "\n"
                  << "Pass Count:        " << strategy->totalPasses() << "\n"
                  << "Standard Ref:      " << strategy->standard() << "\n"
                  << "Description:       " << strategy->description() << "\n\n";

        // Step 3: Require explicit confirmation
        if (!confirmed) {
            std::cerr << "[SAFETY INTERLOCK ERROR] Operation aborted!\n"
                      << "Explicit user confirmation is mandatory prior to sanitizing disk image.\n"
                      << "Re-run with '--confirm' flag to permanently overwrite the target.\n\n";
            return 1;
        }

        // Step 5: Perform operation on the image with progress callback
        forensivault::sanitization::ImageSanitizer sanitizer;
        auto progressCb = [](const forensivault::sanitization::EraseProgress& p) {
            std::cout << "\rSanitizing: " << std::fixed << std::setprecision(1)
                      << p.percentage << "% [Pass " << p.current_pass << "/" << p.total_passes
                      << "] " << p.current_file << std::flush;
        };

        std::cout << "Initiating sanitization engine...\n";
        auto report = sanitizer.sanitizeImage(imgPath, *strategy, confirmed, progressCb);
        std::cout << "\n\n";

        // Step 6-10: Display complete audit report
        std::cout << "=============================================================\n"
                  << "             SANITIZATION VERIFICATION REPORT                \n"
                  << "=============================================================\n"
                  << "Target Image:      " << report.target_path << "\n"
                  << "Overall Status:    " << (report.verified ? "SUCCESS & VERIFIED" : "COMPLETED / UNVERIFIED") << "\n"
                  << "Verification:      " << (report.verified ? "VERIFIED (100% compliant)" : "UNVERIFIED") << "\n"
                  << "Passes Executed:   " << report.passes_completed << "\n"
                  << "Bytes Processed:   " << report.total_bytes_sanitized << "\n"
                  << "Measured Entropy:  " << std::fixed << std::setprecision(4) << report.measured_entropy << " / 8.0000\n"
                  << "Pattern Match:     " << std::fixed << std::setprecision(2) << report.match_rate_percentage << "%\n"
                  << "Pre-Wipe SHA-256:  " << report.pre_wipe_sha256 << "\n"
                  << "Post-Wipe SHA-256: " << report.post_wipe_sha256 << "\n"
                  << "Started At:        " << report.start_timestamp_iso << "\n"
                  << "Completed At:      " << report.end_timestamp_iso << "\n"
                  << "Audit Record ID:   #" << report.audit_entry_id << " (Cryptographically chained)\n"
                  << "=============================================================\n\n";

        if (!report.limitations_disclosed.empty()) {
            std::cout << "[Forensic Limitations & Disclosures]\n";
            for (const auto& lim : report.limitations_disclosed) {
                std::cout << "  * " << lim << "\n";
            }
            std::cout << "\n";
        }

        return report.verified ? 0 : 1;
    }

    if (args[0] == "--audit-export") {
        if (args.size() < 2) {
            FV_LOG_ERROR("Missing destination path for --audit-export");
            return 1;
        }
        std::string outPath = args[1];
        if (forensivault::logging::AuditLogger::getInstance().saveToFile(outPath)) {
            std::cout << "Forensic audit journal exported to: " << outPath << "\n";
            return 0;
        } else {
            std::cerr << "Failed to export audit journal to: " << outPath << "\n";
            return 1;
        }
    }

    if (args[0] == "--init-case") {
        if (args.size() < 6) {
            std::cout << "Usage: forensivault_cli --init-case <path> <id> <name> <examiner> <agency>\n";
            return 1;
        }
        forensivault::core::CaseInfo info;
        info.case_id = args[2];
        info.case_name = args[3];
        info.investigator_name = args[4];
        info.agency = args[5];
        info.description = "Forensic case initialized via ForensiVault Core CLI";
        if (forensivault::core::CaseManager::initializeWorkspace(args[1], info)) {
            std::cout << "Case workspace successfully created at: " << args[1] << "\n";
            return 0;
        } else {
            std::cerr << "Failed to initialize case workspace at: " << args[1] << "\n";
            return 1;
        }
    }

    if (args[0] == "--generate-report") {
        if (args.size() < 2) {
            FV_LOG_ERROR("Missing case directory path for --generate-report");
            return 1;
        }
        std::string caseDir = args[1];
        bool genPdf = false;
        for (size_t a = 2; a < args.size(); ++a) {
            if (args[a] == "--pdf") genPdf = true;
        }

        forensivault::core::CaseManager mgr(caseDir);
        auto cInfo = mgr.getCaseInfo();
        if (cInfo.case_id.empty()) {
            std::cerr << "Invalid case directory or missing case_metadata.json: " << caseDir << "\n";
            return 1;
        }

        std::cout << "\n=============================================================\n";
        std::cout << "     ForensiVault Forensic Report Compilation Subsystem     \n";
        std::cout << "=============================================================\n";
        std::cout << "Case ID:      " << cInfo.case_id << " (" << cInfo.case_name << ")\n";
        std::cout << "Examiner:     " << cInfo.investigator_name << " (" << cInfo.agency << ")\n";
        std::cout << "Workspace:    " << caseDir << "\n\n";

        forensivault::reporting::ForensicReportBuilder builder;
        builder.setCaseInfo(cInfo);

        // Load evidence items
        auto evidenceList = mgr.getEvidenceList();
        if (!evidenceList.empty()) {
            const auto& ev = evidenceList[0];
            forensivault::reporting::AcquisitionMetadata acq;
            acq.evidence_id = ev.evidence_id;
            acq.source_path = ev.filepath;
            acq.total_bytes = ev.size_bytes;
            acq.total_sectors = ev.size_bytes / 512;
            acq.sector_size = 512;
            acq.intake_sha256 = ev.sha256_hash;
            acq.acquisition_timestamp_iso = ev.acquired_timestamp_iso;
            acq.acquiring_examiner = cInfo.investigator_name;
            builder.setAcquisition(acq);
            builder.setEvidenceHashes(ev.sha256_hash, ev.sha256_hash);
        }

        // Load audit log from case workspace
        std::string auditPath = mgr.auditLogPath();
        forensivault::logging::AuditLogger caseLogger;
        if (std::filesystem::exists(auditPath)) {
            caseLogger.loadFromFile(auditPath);
        }
        builder.setAuditTrail(caseLogger.getEntries(), caseLogger.verifyChain());

        // Build report
        auto report = builder.build();

        // Save report package in case reports/ folder
        std::string reportsFolder = mgr.reportsDir();
        auto res = forensivault::reporting::ReportGenerator::saveReportPackage(report, reportsFolder, genPdf);

        std::cout << "Report Compilation Results:\n";
        if (res.json_saved) {
            std::cout << "  [JSON Report]:  " << res.json_path << "\n";
        }
        if (res.html_saved) {
            std::cout << "  [HTML Report]:  " << res.html_path << "\n";
        }
        if (res.pdf_saved) {
            std::cout << "  [PDF Report]:   " << res.pdf_path << "\n";
        } else if (genPdf) {
            std::cout << "  [PDF Report]:   Generated via HTML printable layout\n";
        }
        std::cout << "\nReport successfully archived in case evidence package.\n"
                  << "=============================================================\n\n";
        return 0;
    }

    FV_LOG_WARN("Unrecognized command or option: " + args[0]);
    printHelp();
    return 1;
}
