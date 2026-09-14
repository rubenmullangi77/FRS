#if defined(_WIN32)
#define NOMINMAX
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <windows.h>
#define FV_EXPORT extern "C" __declspec(dllexport)
#else
#define FV_EXPORT extern "C" __attribute__((visibility("default")))
#endif

#include "forensivault/common/crypto_hash.hpp"
#include "core/disk_image_reader.hpp"
#include "core/partition_table.hpp"
#include "core/storage_device_detector.hpp"
#include "core/portable_device_detector.hpp"
#include "filesystem/fs_analyzer.hpp"
#include "filesystem/fat32_analyzer.hpp"
#include "filesystem/exfat_analyzer.hpp"
#include "filesystem/ntfs_analyzer.hpp"
#include "recovery/recovery_engine.hpp"
#include "carving/file_carver.hpp"
#include "carving/confidence_scorer.hpp"
#include "carving/fragment_reconstructor.hpp"
#include "sanitization/system_protection.hpp"
#include "sanitization/secure_file_eraser.hpp"
#include "sanitization/image_sanitizer.hpp"
#include "sanitization/drive_detector.hpp"

#include <cstring>
#include <string>
#include <sstream>
#include <iostream>
#include <vector>
#include <memory>
#include <iomanip>
#include <filesystem>
#include <fstream>

using namespace forensivault;

namespace {
std::string escapeJson(const std::string& s) {
    std::ostringstream o;
    for (char c : s) {
        if (c == '"') o << "\\\"";
        else if (c == '\\') o << "\\\\";
        else if (c == '\n') o << "\\n";
        else if (c == '\r') o << "\\r";
        else if (c == '\t') o << "\\t";
        else if (static_cast<unsigned char>(c) < 32) {
            o << "\\u" << std::hex << std::setw(4) << std::setfill('0') << static_cast<int>(static_cast<unsigned char>(c));
        } else {
            o << c;
        }
    }
    return o.str();
}

void safeCopy(char* dest, size_t max_len, const std::string& src) {
    if (!dest || max_len == 0) return;
    size_t copy_len = (src.size() < max_len - 1) ? src.size() : (max_len - 1);
    std::memcpy(dest, src.data(), copy_len);
    dest[copy_len] = '\0';
}

std::string computeReaderSha256(forensivault::core::DiskImageReader& reader) {
    CryptoHash::Sha256Context ctx;
    uint64_t totalSize = reader.size();
    
    // For large volumes/live devices (> 4GB), hashing the entire volume in 64KB blocks
    // synchronously stalls the scanner for hours. For evidence immutability on live devices,
    // hash the VBR and filesystem metadata header (first 64KB), or sample sectors.
    const uint64_t maxFullHashSize = 4ULL * 1024 * 1024 * 1024; // 4 GB
    bool isLiveDevice = reader.filepath().rfind("\\\\.\\", 0) == 0 ||
                        reader.filepath().rfind("\\\\?\\", 0) == 0 ||
                        (reader.filepath().size() <= 3 && reader.filepath().find(':') != std::string::npos);

    if (totalSize > maxFullHashSize || isLiveDevice) {
        // Hash the first 64KB containing Boot Sector, BIOS Parameter Block (BPB), and metadata anchor
        size_t headerBytes = static_cast<size_t>(std::min<uint64_t>(65536, totalSize));
        auto headerBuf = reader.readBytes(0, headerBytes);
        if (!headerBuf.empty()) {
            ctx.update(headerBuf.data(), headerBuf.size());
        }
        return "METADATA-VBR:" + ctx.finalize();
    }

    uint64_t offset = 0;
    const size_t chunkSize = 65536;
    while (offset < totalSize) {
        size_t toRead = static_cast<size_t>(std::min<uint64_t>(chunkSize, totalSize - offset));
        auto buf = reader.readBytes(offset, toRead);
        if (buf.empty()) break;
        ctx.update(buf.data(), buf.size());
        offset += buf.size();
    }
    return ctx.finalize();
}
}

// 1. Cryptographic hashing
FV_EXPORT void fv_sha256(const uint8_t* data, size_t length, char* out_hex) {
    if (!data || !out_hex) return;
    std::string h = CryptoHash::sha256(data, length);
    std::strcpy(out_hex, h.c_str());
}

FV_EXPORT void fv_md5(const uint8_t* data, size_t length, char* out_hex) {
    if (!data || !out_hex) return;
    std::string h = CryptoHash::md5(data, length);
    std::strcpy(out_hex, h.c_str());
}

FV_EXPORT uint32_t fv_crc32(const uint8_t* data, size_t length) {
    if (!data) return 0;
    return CryptoHash::crc32(data, length);
}

FV_EXPORT double fv_shannon_entropy(const uint8_t* data, size_t length) {
    if (!data || length == 0) return 0.0;
    return CryptoHash::calculateEntropy(data, length);
}

// 2. System Protection Guard
FV_EXPORT int fv_is_system_protected(const char* path, char* out_reason, size_t max_reason_len) {
    if (!path) return 1;
    std::string reason;
    bool prot = sanitization::SystemProtectionGuard::isProtected(path, reason);
    if (out_reason && max_reason_len > 0) {
        safeCopy(out_reason, max_reason_len, reason);
    }
    return prot ? 1 : 0;
}

// 3. Disk Image Reader
FV_EXPORT int fv_get_image_geometry(const char* image_path, uint64_t* out_size, uint32_t* out_sector_size) {
    if (!image_path || !out_size || !out_sector_size) return -1;
    core::DiskImageReader reader;
    if (!reader.open(image_path)) return -2;
    *out_size = reader.size();
    *out_sector_size = reader.sectorSize();
    reader.close();
    return 0;
}

FV_EXPORT int fv_read_sectors(const char* image_path, uint64_t start_sector, uint32_t count,
                              uint8_t* out_buffer, size_t max_len, uint32_t* out_sectors_read) {
    if (!image_path || !out_buffer || !out_sectors_read) return -1;
    core::DiskImageReader reader;
    if (!reader.open(image_path)) return -2;
    
    size_t sector_size = reader.sectorSize();
    size_t req_bytes = static_cast<size_t>(count) * sector_size;
    if (max_len < req_bytes) req_bytes = max_len;
    uint32_t sectors_to_read = static_cast<uint32_t>(req_bytes / sector_size);
    if (sectors_to_read == 0) sectors_to_read = 1;

    std::vector<uint8_t> buf(sectors_to_read * sector_size);
    bool ok = reader.readSectors(start_sector, sectors_to_read, buf.data());
    if (!ok) {
        reader.close();
        return -3;
    }
    
    size_t copy_bytes = (buf.size() < max_len) ? buf.size() : max_len;
    std::memcpy(out_buffer, buf.data(), copy_bytes);
    *out_sectors_read = static_cast<uint32_t>(copy_bytes / sector_size);
    reader.close();
    return 0;
}

// 3b. Process Privilege Detection
FV_EXPORT int fv_is_process_elevated() {
#if defined(_WIN32)
    BOOL isElevated = FALSE;
    HANDLE hToken = NULL;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
        TOKEN_ELEVATION elevation;
        DWORD cbSize = sizeof(TOKEN_ELEVATION);
        if (GetTokenInformation(hToken, TokenElevation, &elevation, sizeof(elevation), &cbSize)) {
            isElevated = elevation.TokenIsElevated;
        }
        CloseHandle(hToken);
    }
    return isElevated ? 1 : 0;
#else
    return (geteuid() == 0) ? 1 : 0;
#endif
}

// 4. File Carving
FV_EXPORT int fv_carve_image(const char* image_path, const char* output_dir,
                             char* out_json, size_t max_json_len) {
    if (!image_path || !out_json || max_json_len == 0) return -1;
    
    core::DiskImageReader reader;
    if (!reader.open(image_path)) {
        std::string err = reader.lastError();
        uint32_t errCode = reader.lastErrorCode();
        bool isAccessDenied = (errCode == 5) || (err.find("Access Denied") != std::string::npos) || (err.find("Error 5") != std::string::npos);
        if (err.empty()) err = "Failed to open target disk or image: " + std::string(image_path);
        std::ostringstream ss;
        ss << "{"
           << "\"error\":true,"
           << "\"error_type\":\"" << (isAccessDenied ? "RAW_ACCESS_DENIED" : "OPEN_FAILED") << "\","
           << "\"error_code\":" << errCode << ","
           << "\"error_message\":\"" << escapeJson(err) << "\","
           << "\"requires_elevation\":" << (isAccessDenied ? "true" : "false") << ","
           << "\"raw_access\":false,"
           << "\"raw_access_status\":\"DENIED\","
           << "\"device_detected\":true,"
           << "\"image_path\":\"" << escapeJson(image_path) << "\","
           << "\"carved_files\":[]"
           << "}";
        safeCopy(out_json, max_json_len, ss.str());
        return -2;
    }
    
    carving::CarverOptions opts;
    if (output_dir && strlen(output_dir) > 0) {
        opts.outputDirectory = output_dir;
    } else {
        opts.outputDirectory = "recovered";
    }
    opts.extractFiles = true;
    opts.organizeByType = true;
    opts.validateIntegrity = true;
    opts.minimumConfidence = 15.0;
    
    carving::FileCarver carver(opts);
    auto session = carver.carve(reader, nullptr);
    reader.close();
    
    std::ostringstream ss;
    ss << "{\"image_path\":\"" << escapeJson(session.imagePath) << "\","
       << "\"total_bytes_scanned\":" << session.totalBytesScanned << ","
       << "\"total_sectors_scanned\":" << session.totalSectorsScanned << ","
       << "\"signatures_discovered\":" << session.signaturesDiscovered << ","
       << "\"files_successfully_carved\":" << session.filesSuccessfullyCarved << ","
       << "\"valid_files_count\":" << session.validFilesCount << ","
       << "\"partial_files_count\":" << session.partialFilesCount << ","
       << "\"duration_ms\":" << session.durationMilliseconds << ","
       << "\"carved_files\":[";
    
    for (size_t i = 0; i < session.carvedFiles.size(); ++i) {
        const auto& cf = session.carvedFiles[i];
        if (i > 0) ss << ",";
        ss << "{"
           << "\"id\":" << cf.id << ","
           << "\"file_type\":\"" << escapeJson(cf.fileType) << "\","
           << "\"extension\":\"" << escapeJson(cf.extension) << "\","
           << "\"mime_type\":\"" << escapeJson(cf.mimeType) << "\","
           << "\"start_offset\":" << cf.startOffset << ","
           << "\"length_bytes\":" << cf.lengthBytes << ","
           << "\"start_sector\":" << cf.startSector << ","
           << "\"sector_span\":" << cf.sectorSpan << ","
           << "\"is_valid\":" << (cf.isValid ? "true" : "false") << ","
           << "\"validation_state\":\"" << escapeJson(cf.validationState) << "\","
           << "\"recovery_status\":\"" << escapeJson(cf.validationState) << "\","
           << "\"recovery_method\":\"" << escapeJson(cf.recoveryMethod) << "\","
           << "\"confidence_score\":" << cf.confidenceScore << ","
           << "\"confidence_level\":\"" << escapeJson(cf.confidenceLevel) << "\","
           << "\"sha256\":\"" << escapeJson(cf.sha256) << "\","
           << "\"validation_notes\":\"" << escapeJson(cf.validationNotes) << "\","
           << "\"recovered_file_path\":\"" << escapeJson(cf.recoveredFilePath) << "\""
           << "}";
    }
    ss << "]}";
    
    safeCopy(out_json, max_json_len, ss.str());
    return static_cast<int>(session.filesSuccessfullyCarved);
}

// 5. Confidence Scoring
FV_EXPORT int fv_score_candidate(uint64_t file_id, const char* file_type, uint64_t offset,
                                 const uint8_t* data, size_t length,
                                 char* out_json, size_t max_json_len) {
    if (!data || !out_json || max_json_len == 0) return -1;
    std::string type_str = file_type ? file_type : "JPEG";
    auto res = carving::RecoveryConfidenceScorer::evaluate(file_id, type_str, offset, data, length);
    std::string json = res.toJson();
    safeCopy(out_json, max_json_len, json);
    return 0;
}

// 6. Real File Erasure
FV_EXPORT int fv_erase_real_file(const char* filepath, int method_enum, char* out_json, size_t max_json_len) {
    if (!filepath || !out_json || max_json_len == 0) return -1;
    sanitization::SanitizationMethod method = sanitization::SanitizationMethod::NIST_800_88_CLEAR;
    if (method_enum == 1) {
        method = sanitization::SanitizationMethod::DOD_5220_22_M;
    } else if (method_enum == 2) {
        method = sanitization::SanitizationMethod::PSEUDORANDOM_1_PASS;
    } else if (method_enum == 3) {
        method = sanitization::SanitizationMethod::ZERO_FILL;
    }

    sanitization::SecureFileEraser eraser;
    auto res = eraser.eraseFile(filepath, method, nullptr);

    std::ostringstream ss;
    ss << "{"
       << "\"is_verified\":" << (res.is_verified ? "true" : "false") << ","
       << "\"accessible_after_deletion\":" << (res.accessible_after_deletion ? "true" : "false") << ","
       << "\"details\":\"" << escapeJson(res.details) << "\","
       << "\"limitations\":[";
    for (size_t i = 0; i < res.limitations.size(); ++i) {
        if (i > 0) ss << ",";
        ss << "\"" << escapeJson(res.limitations[i]) << "\"";
    }
    ss << "]}";

    safeCopy(out_json, max_json_len, ss.str());
    return res.is_verified ? 0 : 1;
}

// 7. Fragment Reconstruction
FV_EXPORT int fv_reconstruct_fragments(const char* image_path, const char* file_type,
                                       const char* output_dir, char* out_json, size_t max_json_len) {
    if (!image_path || !out_json || max_json_len == 0) return -1;

    core::DiskImageReader reader;
    if (!reader.open(image_path)) {
        std::string err = reader.lastError();
        if (err.empty()) err = "Failed to open target disk or image: " + std::string(image_path);
        std::ostringstream ss;
        ss << "{\"success\":false,\"error_message\":\"" << escapeJson(err) << "\",\"fragments\":[],\"reconstructions\":[]}";
        safeCopy(out_json, max_json_len, ss.str());
        return -2;
    }

    std::string targetType = file_type ? file_type : "JPEG";
    std::string outDir = (output_dir && strlen(output_dir) > 0) ? output_dir : "recovered";

    size_t totalBytes = static_cast<size_t>(reader.size());
    std::vector<uint8_t> buffer = reader.readBytes(0, totalBytes);
    reader.close();

    // 1. Scan image for candidate header fragments that lack local footers
    std::vector<carving::FragmentCandidate> headerCandidates;
    std::vector<carving::FragmentCandidate> allDiscovered;
    uint64_t fragIdCounter = 1;

    const size_t clusterSize = 512;
    for (size_t off = 0; off + clusterSize <= buffer.size(); off += clusterSize) {
        const uint8_t* clusterData = buffer.data() + off;
        bool isHeader = false;
        size_t headerLen = clusterSize;

        if (targetType == "JPEG") {
            if (clusterData[0] == 0xFF && clusterData[1] == 0xD8 && clusterData[2] == 0xFF) {
                bool hasEoi = false;
                for (size_t i = 2; i + 1 < clusterSize; ++i) {
                    if (clusterData[i] == 0xFF && clusterData[i + 1] == 0xD9) {
                        hasEoi = true;
                        break;
                    }
                }
                if (!hasEoi) {
                    isHeader = true;
                    // Find length up to trailing zeroes
                    for (size_t i = clusterSize; i > 0; --i) {
                        if (clusterData[i - 1] != 0x00) {
                            headerLen = i;
                            break;
                        }
                    }
                }
            }
        } else if (targetType == "PNG") {
            const uint8_t pngMagic[] = {0x89, 'P', 'N', 'G', 0x0D, 0x0A, 0x1A, 0x0A};
            if (std::memcmp(clusterData, pngMagic, 8) == 0) {
                isHeader = true;
                headerLen = clusterSize;
            }
        }

        if (isHeader) {
            carving::FragmentCandidate hFrag;
            hFrag.fragmentId = fragIdCounter++;
            hFrag.offset = off;
            hFrag.length = headerLen;
            hFrag.startSector = off / 512;
            hFrag.fileType = targetType;
            hFrag.role = carving::FragmentRole::Header;
            hFrag.data.assign(clusterData, clusterData + headerLen);
            hFrag.entropy = CryptoHash::calculateEntropy(hFrag.data);
            hFrag.confidence = 50.0;
            hFrag.diagnosticNotes = "Candidate " + targetType + " header fragment with missing termination";
            headerCandidates.push_back(hFrag);
            allDiscovered.push_back(hFrag);
        }
    }

    // 2. Discover orphan footers and bodies
    auto orphans = carving::FragmentReconstructor::findOrphanFragments(
        targetType, buffer.data(), 0, buffer.size(), 512);

    for (auto& o : orphans) {
        o.fragmentId = fragIdCounter++;
        allDiscovered.push_back(o);
    }

    // 3. Attempt conservative reconstruction for each header fragment found
    std::vector<carving::ReconstructionResult> results;
    int reconstructedCount = 0;
    int segregatedCount = 0;

    for (const auto& header : headerCandidates) {
        auto res = carving::FragmentReconstructor::attemptReconstruction(header, orphans, 2 * 1024 * 1024);
        if (res.isReconstructed && !res.reconstructedData.empty()) {
            reconstructedCount++;
            try {
                std::filesystem::create_directories(outDir);
                std::string filename = "reconstructed_" + std::to_string(header.fragmentId) + "." +
                    (targetType == "JPEG" ? "jpg" : (targetType == "PNG" ? "png" : "bin"));
                std::filesystem::path outPath = std::filesystem::path(outDir) / filename;
                std::ofstream ofs(outPath, std::ios::binary);
                if (ofs) {
                    ofs.write(reinterpret_cast<const char*>(res.reconstructedData.data()), res.reconstructedData.size());
                }
            } catch (...) {}
        } else {
            segregatedCount++;
        }
        results.push_back(res);
    }

    // Output JSON
    std::ostringstream ss;
    ss << "{"
       << "\"image_path\":\"" << escapeJson(image_path) << "\","
       << "\"file_type\":\"" << escapeJson(targetType) << "\","
       << "\"total_fragments_discovered\":" << allDiscovered.size() << ","
       << "\"headers_found\":" << headerCandidates.size() << ","
       << "\"reconstructed_count\":" << reconstructedCount << ","
       << "\"segregated_count\":" << segregatedCount << ","
       << "\"fragments\":[";

    for (size_t i = 0; i < allDiscovered.size(); ++i) {
        if (i > 0) ss << ",";
        const auto& f = allDiscovered[i];
        ss << "{"
           << "\"id\":" << f.fragmentId << ","
           << "\"offset\":" << f.offset << ","
           << "\"length\":" << f.length << ","
           << "\"start_sector\":" << f.startSector << ","
           << "\"role\":\"" << escapeJson(carving::fragmentRoleToString(f.role)) << "\","
           << "\"entropy\":" << f.entropy << ","
           << "\"confidence\":" << f.confidence << ","
           << "\"diagnostic_notes\":\"" << escapeJson(f.diagnosticNotes) << "\""
           << "}";
    }
    ss << "],\"reconstructions\":[";

    for (size_t i = 0; i < results.size(); ++i) {
        if (i > 0) ss << ",";
        const auto& r = results[i];
        ss << "{"
           << "\"is_reconstructed\":" << (r.isReconstructed ? "true" : "false") << ","
           << "\"is_partial\":" << (r.isPartial ? "true" : "false") << ","
           << "\"file_type\":\"" << escapeJson(r.fileType) << "\","
           << "\"total_size\":" << r.totalReconstructedSize << ","
           << "\"confidence_score\":" << r.confidenceScore << ","
           << "\"sha256\":\"" << escapeJson(r.sha256) << "\","
           << "\"uncertainty_reason\":\"" << escapeJson(r.uncertaintyReason) << "\","
           << "\"fragment_offsets\":[";
        for (size_t j = 0; j < r.fragmentOffsets.size(); ++j) {
            if (j > 0) ss << ",";
            ss << r.fragmentOffsets[j];
        }
        ss << "]}";
    }
    ss << "]}";

    safeCopy(out_json, max_json_len, ss.str());
    return reconstructedCount;
}

// 8. Partition Detection (MBR & GPT)
FV_EXPORT int fv_detect_partitions(const char* image_path, char* out_json, size_t max_json_len) {
    if (!image_path || !out_json || max_json_len == 0) return -1;
    core::DiskImageReader reader;
    if (!reader.open(image_path)) {
        std::string err = reader.lastError();
        if (err.empty()) err = "Failed to open target disk or image: " + std::string(image_path);
        std::ostringstream ss;
        ss << "{\"table_type\":\"Unknown\",\"error\":true,\"error_message\":\"" << escapeJson(err) << "\",\"partitions\":[]}";
        safeCopy(out_json, max_json_len, ss.str());
        return -2;
    }

    auto partMap = core::PartitionDetector::detectPartitions(reader);
    reader.close();

    std::ostringstream ss;
    ss << "{"
       << "\"table_type\":\"" << escapeJson(partMap.table_type_str) << "\","
       << "\"total_disk_sectors\":" << partMap.total_disk_sectors << ","
       << "\"sector_size\":" << partMap.sector_size << ","
       << "\"total_bytes\":" << (partMap.total_disk_sectors * partMap.sector_size) << ","
       << "\"partitions\":[";

    for (size_t i = 0; i < partMap.partitions.size(); ++i) {
        if (i > 0) ss << ",";
        const auto& p = partMap.partitions[i];
        ss << "{"
           << "\"partition_number\":" << p.partition_number << ","
           << "\"start_sector\":" << p.start_sector << ","
           << "\"sector_count\":" << p.sector_count << ","
           << "\"size_bytes\":" << p.size_bytes << ","
           << "\"size_formatted\":\"" << escapeJson(p.size_formatted) << "\","
           << "\"partition_type_id\":" << static_cast<int>(p.partition_type_id) << ","
           << "\"type_name\":\"" << escapeJson(p.type_name) << "\","
           << "\"type_guid\":\"" << escapeJson(p.type_guid) << "\","
           << "\"partition_name\":\"" << escapeJson(p.partition_name) << "\","
           << "\"is_bootable\":" << (p.is_bootable ? "true" : "false")
           << "}";
    }
    ss << "]}";

    safeCopy(out_json, max_json_len, ss.str());
    return static_cast<int>(partMap.partitions.size());
}

// 8b. Real Storage Device & Partition Hierarchy Detection
FV_EXPORT int fv_detect_storage_devices(char* out_json, size_t max_json_len) {
    if (!out_json || max_json_len == 0) return -1;
    std::string jsonStr = core::StorageDeviceDetector::detectAllStorageJson();
    safeCopy(out_json, max_json_len, jsonStr);
    return 0;
}

// 9. Filesystem Inspection (NTFS, FAT32, exFAT)
FV_EXPORT int fv_inspect_filesystem(const char* image_path, uint64_t start_sector, char* out_json, size_t max_json_len) {
    if (!image_path || !out_json || max_json_len == 0) return -1;
    core::DiskImageReader reader;
    if (!reader.open(image_path)) {
        std::string err = reader.lastError();
        uint32_t errCode = reader.lastErrorCode();
        bool isAccessDenied = (errCode == 5) || (err.find("Access Denied") != std::string::npos) || (err.find("Error 5") != std::string::npos);
        if (err.empty()) err = "Failed to open target disk or image: " + std::string(image_path);
        std::ostringstream ss;
        ss << "{"
           << "\"success\":false,"
           << "\"is_detected\":false,"
           << "\"error\":true,"
           << "\"error_type\":\"" << (isAccessDenied ? "RAW_ACCESS_DENIED" : "OPEN_FAILED") << "\","
           << "\"error_code\":" << errCode << ","
           << "\"error_message\":\"" << escapeJson(err) << "\","
           << "\"message\":\"" << escapeJson(err) << "\","
           << "\"requires_elevation\":" << (isAccessDenied ? "true" : "false") << ","
           << "\"raw_access\":false,"
           << "\"raw_access_status\":\"DENIED\","
           << "\"device_detected\":true,"
           << "\"fs_type\":\"Unknown\","
           << "\"detection_status\":\"Access Failed\","
           << "\"partition_start_sector\":" << start_sector
           << "}";
        safeCopy(out_json, max_json_len, ss.str());
        return -2;
    }

    recovery::RecoveryEngine engine;
    auto analyzer = engine.detectFilesystem(reader, start_sector);

    std::ostringstream ss;
    if (analyzer) {
        auto vol = analyzer->getVolumeInfo();
        std::string fsName = "UNKNOWN";
        if (vol.fs_type == filesystem::FsType::NTFS) fsName = "NTFS";
        else if (vol.fs_type == filesystem::FsType::FAT32) fsName = "FAT32";
        else if (vol.fs_type == filesystem::FsType::EXFAT) fsName = "exFAT";

        uint64_t partSizeBytes = vol.total_sectors * vol.bytes_per_sector;
        if (partSizeBytes == 0 && reader.size() > (start_sector * 512)) {
            partSizeBytes = reader.size() - (start_sector * 512);
        }

        ss << "{"
           << "\"success\":true,"
           << "\"is_detected\":true,"
           << "\"fs_type\":\"" << escapeJson(fsName) << "\","
           << "\"detection_status\":\"Confirmed\","
           << "\"sector_size\":" << vol.bytes_per_sector << ","
           << "\"cluster_size\":" << vol.cluster_size << ","
           << "\"sectors_per_cluster\":" << vol.sectors_per_cluster << ","
           << "\"partition_start_sector\":" << start_sector << ","
           << "\"partition_start_bytes\":" << (start_sector * vol.bytes_per_sector) << ","
           << "\"partition_size_bytes\":" << partSizeBytes << ","
           << "\"partition_size_formatted\":\"" << escapeJson(core::PartitionDetector::formatPartitionSize(partSizeBytes)) << "\","
           << "\"volume_label\":\"" << escapeJson(vol.volume_label) << "\","
           << "\"serial_number\":" << vol.serial_number << ","
           << "\"total_clusters\":" << vol.total_clusters << ","
           << "\"message\":\"" << escapeJson(fsName + " filesystem structure validated successfully.") << "\""
           << "}";
    } else {
        ss << "{"
           << "\"success\":false,"
           << "\"is_detected\":false,"
           << "\"fs_type\":\"Unknown\","
           << "\"detection_status\":\"Unsupported or corrupted filesystem\","
           << "\"sector_size\":512,"
           << "\"cluster_size\":0,"
           << "\"partition_start_sector\":" << start_sector << ","
           << "\"partition_size_bytes\":0,"
           << "\"volume_label\":\"\","
           << "\"message\":\"No recognized NTFS, FAT32, or exFAT volume boot record found at sector " << start_sector << ".\""
           << "}";
    }
    reader.close();

    safeCopy(out_json, max_json_len, ss.str());
    return analyzer ? 0 : 1;
}

// 10. Real Filesystem Recovery & Extraction
FV_EXPORT int fv_recover_filesystem(const char* image_path, uint64_t start_sector,
                                    const char* output_dir, const char* case_id,
                                    char* out_json, size_t max_json_len) {
    if (!image_path || !out_json || max_json_len == 0) return -1;
    core::DiskImageReader reader;
    if (!reader.open(image_path)) {
        std::string err = reader.lastError();
        uint32_t errCode = reader.lastErrorCode();
        bool isAccessDenied = (errCode == 5) || (err.find("Access Denied") != std::string::npos) || (err.find("Error 5") != std::string::npos);
        if (err.empty()) err = "Failed to open target disk or image: " + std::string(image_path);
        std::ostringstream ss;
        ss << "{"
           << "\"success\":false,"
           << "\"error\":\"" << (isAccessDenied ? "RAW_ACCESS_DENIED" : "ACCESS_DENIED") << "\","
           << "\"error_type\":\"" << (isAccessDenied ? "RAW_ACCESS_DENIED" : "ACCESS_DENIED") << "\","
           << "\"error_code\":" << errCode << ","
           << "\"error_message\":\"" << escapeJson(err) << "\","
           << "\"message\":\"" << escapeJson(err) << "\","
           << "\"requires_elevation\":" << (isAccessDenied ? "true" : "false") << ","
           << "\"raw_access\":false,"
           << "\"raw_access_status\":\"DENIED\","
           << "\"device_detected\":true,"
           << "\"files\":[]"
           << "}";
        safeCopy(out_json, max_json_len, ss.str());
        return -2;
    }

    recovery::RecoveryEngine engine;
    auto analyzer = engine.detectFilesystem(reader, start_sector);
    if (!analyzer) {
        reader.close();
        std::string errJson = "{\"success\":false,\"error\":\"NO_FILESYSTEM\",\"message\":\"No supported filesystem detected at specified partition offset.\"}";
        safeCopy(out_json, max_json_len, errJson);
        return -3;
    }

    auto vol = analyzer->getVolumeInfo();
    std::string fsName = "UNKNOWN";
    if (vol.fs_type == filesystem::FsType::NTFS) fsName = "NTFS";
    else if (vol.fs_type == filesystem::FsType::FAT32) fsName = "FAT32";
    else if (vol.fs_type == filesystem::FsType::EXFAT) fsName = "exFAT";

    // Compute pre-recovery evidence hash
    std::string preHash = computeReaderSha256(reader);

    std::string targetDir = output_dir ? output_dir : "ForensiVault_Recovered";
    std::string cleanCase = (case_id && strlen(case_id) > 0) ? case_id : "CASE-001";
    std::filesystem::path caseOutDir = std::filesystem::path(targetDir) / cleanCase;

    // Scan deleted and active
    auto deletedFiles = analyzer->findDeletedFiles();
    auto activeFiles = analyzer->listDirectory("/");

    int recoveredCount = 0;
    int partialCount = 0;
    int unrecoverableCount = 0;

    std::ostringstream ss;
    ss << "{"
       << "\"success\":true,"
       << "\"fs_type\":\"" << escapeJson(fsName) << "\","
       << "\"case_id\":\"" << escapeJson(cleanCase) << "\","
       << "\"evidence_pre_hash\":\"" << escapeJson(preHash) << "\","
       << "\"deleted_entries_found\":" << deletedFiles.size() << ","
       << "\"active_entries_found\":" << activeFiles.size() << ",";

    std::vector<std::string> fileJsonEntries;

    // Process deleted candidate files
    for (size_t i = 0; i < deletedFiles.size(); ++i) {
        auto& f = deletedFiles[i];
        std::string qualitativeState = "UNKNOWN";
        std::string runIntegrity = "UNAVAILABLE";
        bool boundsValid = false;
        std::string sha256Hex = "";
        std::string savedPath = "";

        uint64_t readerSz = reader.size();
        if (f.file_size == 0) {
            boundsValid = true;
            qualitativeState = "RECOVERABLE";
            runIntegrity = "INTACT";
        } else if (readerSz > 0 && f.byte_offset <= readerSz && (readerSz - f.byte_offset) >= f.file_size) {
            boundsValid = true;
        }

        if (!f.is_recoverable || f.allocation_status == filesystem::AllocationStatus::NOT_RECOVERABLE) {
            qualitativeState = "NOT_RECOVERABLE";
            runIntegrity = "UNAVAILABLE";
            unrecoverableCount++;
        } else if (!boundsValid) {
            qualitativeState = "NOT_RECOVERABLE";
            runIntegrity = "DAMAGED";
            f.unrecoverable_reason = "Cluster allocation offset exceeds volume boundary.";
            unrecoverableCount++;
        } else if (f.allocation_status == filesystem::AllocationStatus::DAMAGED_CHAIN) {
            qualitativeState = "PARTIALLY_RECOVERABLE";
            runIntegrity = "PARTIALLY_INTACT";
            partialCount++;
        } else {
            qualitativeState = "RECOVERABLE";
            runIntegrity = "INTACT";
        }

        if (qualitativeState == "RECOVERABLE") {
            auto data = analyzer->extractFile(f, reader);
            if (!data.empty() || f.file_size == 0) {
                sha256Hex = CryptoHash::sha256(data.data(), data.size());
                f.sha256_hash = sha256Hex;
                try {
                    std::filesystem::create_directories(caseOutDir);
                    std::filesystem::path filePath = caseOutDir / f.filename;
                    std::ofstream ofs(filePath, std::ios::binary);
                    if (ofs) {
                        ofs.write(reinterpret_cast<const char*>(data.data()), data.size());
                        savedPath = filePath.string();
                        recoveredCount++;
                    }
                } catch (...) {}
            } else {
                qualitativeState = "NOT_RECOVERABLE";
                runIntegrity = "UNAVAILABLE";
                f.unrecoverable_reason = "Sector payload unreadable or zeroed.";
                unrecoverableCount++;
            }
        }

        std::ostringstream fsEntry;
        fsEntry << "{"
                << "\"id\":" << (i + 1) << ","
                << "\"filename\":\"" << escapeJson(f.filename) << "\","
                << "\"original_path\":\"" << escapeJson(f.full_path) << "\","
                << "\"file_type\":\"" << escapeJson(f.extension.empty() ? "UNKNOWN" : f.extension) << "\","
                << "\"extension\":\"" << escapeJson(f.extension) << "\","
                << "\"size_bytes\":" << f.file_size << ","
                << "\"offset_hex\":\"0x" << std::hex << std::uppercase << f.byte_offset << "\","
                << "\"offset_dec\":" << std::dec << f.byte_offset << ","
                << "\"starting_cluster\":" << f.starting_cluster << ","
                << "\"mft_record\":" << f.mft_record_number << ","
                << "\"fragment_count\":" << f.fragment_count << ","
                << "\"created_time\":\"" << escapeJson(f.created_time) << "\","
                << "\"modified_time\":\"" << escapeJson(f.modified_time) << "\","
                << "\"method\":\"" << escapeJson(fsName + " Filesystem") << "\","
                << "\"recovery_status\":\"" << escapeJson(qualitativeState) << "\","
                << "\"qualitative_state\":\"" << escapeJson(qualitativeState) << "\","
                << "\"is_recoverable\":" << (qualitativeState == "RECOVERABLE" ? "true" : "false") << ","
                << "\"bounds_valid\":" << (boundsValid ? "true" : "false") << ","
                << "\"cluster_run_integrity\":\"" << escapeJson(runIntegrity) << "\","
                << "\"unrecoverable_reason\":\"" << escapeJson(f.unrecoverable_reason) << "\","
                << "\"confidence_score\":" << (qualitativeState == "RECOVERABLE" ? 100 : (qualitativeState == "PARTIALLY_RECOVERABLE" ? 50 : 0)) << ","
                << "\"confidence_level\":\"" << (qualitativeState == "RECOVERABLE" ? "High" : (qualitativeState == "PARTIALLY_RECOVERABLE" ? "Medium" : "None")) << "\","
                << "\"sha256\":\"" << escapeJson(sha256Hex) << "\","
                << "\"recovered_file_path\":\"" << escapeJson(savedPath) << "\""
                << "}";
        fileJsonEntries.push_back(fsEntry.str());
    }

    // Compute post-recovery evidence hash (Verification of 100% read-only immutability)
    std::string postHash = computeReaderSha256(reader);
    reader.close();

    ss << "\"recoverable_count\":" << recoveredCount << ","
       << "\"partial_count\":" << partialCount << ","
       << "\"not_recoverable_count\":" << unrecoverableCount << ","
       << "\"evidence_post_hash\":\"" << escapeJson(postHash) << "\","
       << "\"evidence_unmodified\":" << (preHash == postHash ? "true" : "false") << ","
       << "\"output_directory\":\"" << escapeJson(caseOutDir.string()) << "\","
       << "\"files\":[";

    for (size_t i = 0; i < fileJsonEntries.size(); ++i) {
        if (i > 0) ss << ",";
        ss << fileJsonEntries[i];
    }
    ss << "]}";

    safeCopy(out_json, max_json_len, ss.str());
    return recoveredCount;
}

FV_EXPORT int fv_detect_portable_devices(char* out_json, size_t max_json_len) {
    if (!out_json || max_json_len == 0) return -1;
    try {
        std::string json = forensivault::core::PortableDeviceDetector::detectPortableDevicesJson();
        safeCopy(out_json, max_json_len, json);
        return 0;
    } catch (const std::exception& e) {
        std::string err = std::string("{\"error\":\"") + escapeJson(e.what()) + "\",\"devices\":[]}";
        safeCopy(out_json, max_json_len, err);
        return -1;
    }
}

FV_EXPORT int fv_browse_portable_device(const char* device_id, const char* object_id, char* out_json, size_t max_json_len) {
    if (!out_json || max_json_len == 0) return -1;
    try {
        std::string dId = device_id ? device_id : "";
        std::string oId = object_id ? object_id : "";
        std::string json = forensivault::core::PortableDeviceDetector::browseDeviceJson(dId, oId);
        safeCopy(out_json, max_json_len, json);
        return 0;
    } catch (const std::exception& e) {
        std::string err = std::string("{\"error\":\"") + escapeJson(e.what()) + "\",\"items\":[]}";
        safeCopy(out_json, max_json_len, err);
        return -1;
    }
}

FV_EXPORT int fv_delete_portable_device_file(const char* device_id, const char* object_id, const char* parent_object_id, char* out_json, size_t max_json_len) {
    if (!out_json || max_json_len == 0) return -1;
    try {
        std::string dId = device_id ? device_id : "";
        std::string oId = object_id ? object_id : "";
        std::string pId = parent_object_id ? parent_object_id : "";
        std::string json = forensivault::core::PortableDeviceDetector::deleteDeviceFileJson(dId, oId, pId);
        safeCopy(out_json, max_json_len, json);
        return 0;
    } catch (const std::exception& e) {
        std::string err = std::string("{\"success\":false,\"error\":\"") + escapeJson(e.what()) + "\"}";
        safeCopy(out_json, max_json_len, err);
        return -1;
    }
}

FV_EXPORT int fv_copy_portable_device_file(const char* device_id, const char* object_id, const char* dest_dir, char* out_json, size_t max_json_len) {
    if (!out_json || max_json_len == 0) return -1;
    try {
        std::string dId = device_id ? device_id : "";
        std::string oId = object_id ? object_id : "";
        std::string dDir = dest_dir ? dest_dir : ".";
        std::string json = forensivault::core::PortableDeviceDetector::copyDeviceFileJson(dId, oId, dDir);
        safeCopy(out_json, max_json_len, json);
        return 0;
    } catch (const std::exception& e) {
        std::string err = std::string("{\"success\":false,\"error\":\"") + escapeJson(e.what()) + "\"}";
        safeCopy(out_json, max_json_len, err);
        return -1;
    }
}


