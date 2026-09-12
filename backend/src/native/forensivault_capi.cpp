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

// 4. File Carving
FV_EXPORT int fv_carve_image(const char* image_path, const char* output_dir,
                             char* out_json, size_t max_json_len) {
    if (!image_path || !out_json || max_json_len == 0) return -1;
    
    core::DiskImageReader reader;
    if (!reader.open(image_path)) return -2;
    
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
    if (!reader.open(image_path)) return -2;

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
