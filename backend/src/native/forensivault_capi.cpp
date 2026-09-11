#define NOMINMAX
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <windows.h>

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

#ifdef _WIN32
#define FV_EXPORT extern "C" __declspec(dllexport)
#else
#define FV_EXPORT extern "C"
#endif

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
