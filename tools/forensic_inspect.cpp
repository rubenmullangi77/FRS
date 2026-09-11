#include "core/disk_image_reader.hpp"
#include "core/binary_utils.hpp"
#include "forensivault/common/crypto_hash.hpp"
#include "recovery/recovery_engine.hpp"
#include <iostream>
#include <iomanip>
#include <vector>
#include <string>

using namespace forensivault::core;
using namespace forensivault::recovery;
using namespace forensivault::filesystem;

namespace {

void printUsage() {
    std::cout << "ForensiVault Diagnostic Tool: forensic-inspect\n"
              << "Usage: forensic-inspect <image> [options]\n\n"
              << "Arguments:\n"
              << "  <image>              Path to raw disk image (.dd, .img, .bin)\n\n"
              << "Options:\n"
              << "  --fs, -f             Perform filesystem analysis (FAT32, exFAT, NTFS)\n"
              << "  --binary, -b         Display binary (bitwise 0/1) representation of first 64 bytes\n"
              << "  --sector <num>, -s   Inspect specific sector number (default: 0)\n"
              << "  --search <hex>       Search for hex byte sequence (e.g. 'FF D8 FF' or '55 AA')\n"
              << "  --help, -h           Show this help manual\n"
              << std::endl;
}

} // anonymous namespace

int main(int argc, char* argv[]) {
    if (argc < 2) {
        printUsage();
        return 1;
    }

    std::string imagePath;
    bool showBinary = false;
    bool analyzeFs = false;
    uint64_t targetSector = 0;
    std::string searchHex;

    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "--help" || arg == "-h") {
            printUsage();
            return 0;
        } else if (arg == "--fs" || arg == "-f") {
            analyzeFs = true;
        } else if (arg == "--binary" || arg == "-b") {
            showBinary = true;
        } else if ((arg == "--sector" || arg == "-s") && i + 1 < argc) {
            targetSector = std::stoull(argv[++i]);
        } else if (arg == "--search" && i + 1 < argc) {
            searchHex = argv[++i];
        } else if (imagePath.empty() && arg[0] != '-') {
            imagePath = arg;
        }
    }

    if (imagePath.empty()) {
        std::cerr << "[ERROR] No disk image file specified.\n";
        printUsage();
        return 1;
    }

    DiskImageReader reader(imagePath);
    if (!reader.isOpen()) {
        std::cerr << "[ERROR] Could not open disk image: " << reader.lastError() << "\n";
        return 1;
    }

    // Display image metadata
    std::cout << "============================================================\n";
    std::cout << "           ForensiVault Image Inspection Tool               \n";
    std::cout << "============================================================\n";
    std::cout << "Image Path:    " << reader.filepath() << "\n";
    std::cout << "Image Size:    " << reader.size() << " bytes ("
              << std::fixed << std::setprecision(2)
              << (static_cast<double>(reader.size()) / (1024.0 * 1024.0)) << " MB)\n";
    std::cout << "Total Sectors: " << reader.totalSectors() << " sectors\n";
    std::cout << "Sector Size:   " << reader.sectorSize() << " bytes\n";
    std::cout << "============================================================\n\n";

    if (analyzeFs) {
        std::cout << "[FILESYSTEM ANALYSIS]\n";
        RecoveryEngine engine;
        auto analyzer = engine.detectFilesystem(reader, 0);
        if (!analyzer) {
            std::cout << "No supported filesystem (FAT32, exFAT, NTFS) detected at sector 0.\n\n";
        } else {
            auto vol = analyzer->getVolumeInfo();
            std::cout << "Detected FS:       " << vol.fs_type << "\n";
            std::cout << "Volume Label:      " << (vol.volume_label.empty() ? "(None)" : vol.volume_label) << "\n";
            std::cout << "Serial Number:     0x" << std::hex << std::uppercase << vol.serial_number << std::dec << "\n";
            std::cout << "Bytes Per Sector:  " << vol.bytes_per_sector << " bytes\n";
            std::cout << "Sectors / Cluster: " << vol.sectors_per_cluster << "\n";
            std::cout << "Cluster Size:      " << vol.cluster_size << " bytes\n";
            std::cout << "Total Sectors:     " << vol.total_sectors << "\n";
            std::cout << "Table Offset:      0x" << std::hex << vol.allocation_table_offset << std::dec << "\n\n";

            std::cout << "--- Active Files (Filesystem Recovery) ---\n";
            auto activeFiles = analyzer->listDirectory("/");
            if (activeFiles.empty()) {
                std::cout << "  (No active files found)\n";
            } else {
                for (const auto& f : activeFiles) {
                    std::cout << "  [ACTIVE] " << std::left << std::setw(16) << f.filename
                              << " Size: " << std::right << std::setw(8) << f.file_size << " bytes"
                              << " Offset: 0x" << std::hex << f.byte_offset << std::dec
                              << " Cluster: " << f.starting_cluster << "\n";
                }
            }
            std::cout << "\n";

            std::cout << "--- Deleted-File Candidates (Filesystem Tombstones) ---\n";
            auto deletedFiles = analyzer->findDeletedFiles();
            if (deletedFiles.empty()) {
                std::cout << "  (No deleted-file candidates found)\n";
            } else {
                for (const auto& f : deletedFiles) {
                    std::cout << "  [DELETED CANDIDATE] " << std::left << std::setw(16) << f.filename
                              << " Size: " << std::right << std::setw(8) << f.file_size << " bytes"
                              << " Offset: 0x" << std::hex << f.byte_offset << std::dec
                              << " Cluster: " << f.starting_cluster << "\n";
                }
            }
            std::cout << "\n";
        }
    }

    // If search was requested
    if (!searchHex.empty()) {
        std::vector<uint8_t> needle = BinaryUtils::fromHex(searchHex);
        if (needle.empty()) {
            std::cerr << "[ERROR] Invalid hex sequence for search: " << searchHex << "\n";
        } else {
            std::cout << "[SEARCH] Searching for sequence: " 
                      << BinaryUtils::toHex(needle) << " (" << needle.size() << " bytes)\n";
            
            // Stream search through image
            std::vector<uint8_t> chunk(64 * 1024);
            uint64_t currentOffset = 0;
            size_t matchCount = 0;

            while (currentOffset < reader.size() && matchCount < 20) {
                size_t toRead = static_cast<size_t>(std::min<uint64_t>(chunk.size(), reader.size() - currentOffset));
                if (!reader.read(currentOffset, chunk.data(), toRead)) break;

                auto matches = BinaryUtils::findAll(chunk.data(), toRead, needle.data(), needle.size());
                for (uint64_t m : matches) {
                    uint64_t absOffset = currentOffset + m;
                    uint64_t sector = BinaryUtils::byteToSector(absOffset, reader.sectorSize());
                    uint32_t rem = BinaryUtils::offsetWithinSector(absOffset, reader.sectorSize());
                    std::cout << "  Match #" << (++matchCount) << " found at offset 0x" 
                              << std::hex << std::uppercase << absOffset 
                              << " (Sector " << std::dec << sector << " + " << rem << " bytes)\n";
                    if (matchCount >= 20) break;
                }
                
                if (toRead <= needle.size()) break;
                currentOffset += (toRead - needle.size() + 1);
            }

            std::cout << "Search complete. Total matches reported: " << matchCount << "\n\n";
        }
    }

    // Read target sector (default sector 0)
    std::cout << "[SECTOR DUMP: Sector " << targetSector << " (512 bytes)]\n";
    std::vector<uint8_t> sectorData = reader.readSector(targetSector);
    if (sectorData.empty()) {
        std::cerr << "[ERROR] Failed to read sector " << targetSector << ": " << reader.lastError() << "\n";
        return 1;
    }

    // SHA-256 of the inspected sector
    std::string sectorSha = BinaryUtils::sha256(sectorData);
    std::cout << "SHA-256 (Sector " << targetSector << "): " << sectorSha << "\n\n";

    // Formatted hex dump
    uint64_t baseOffset = BinaryUtils::sectorToByteOffset(targetSector, reader.sectorSize());
    std::string hexDump = BinaryUtils::formatHexDump(sectorData, baseOffset, 16);
    std::cout << hexDump << "\n";

    // If binary bitwise representation was requested
    if (showBinary) {
        std::cout << "[BITWISE BINARY REPRESENTATION (First 32 bytes)]\n";
        size_t binCount = std::min<size_t>(32, sectorData.size());
        for (size_t i = 0; i < binCount; ++i) {
            std::cout << "0x" << std::hex << std::uppercase << std::setfill('0') << std::setw(4) << (baseOffset + i)
                      << "  [0x" << BinaryUtils::byteToHex(sectorData[i]) << "]  "
                      << BinaryUtils::byteToBinary(sectorData[i]) << "  '"
                      << BinaryUtils::toAscii(sectorData[i]) << "'\n";
        }
        std::cout << "\n";
    }

    return 0;
}
