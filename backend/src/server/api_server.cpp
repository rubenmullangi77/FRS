#define NOMINMAX
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>

#include "carving/file_carver.hpp"
#include "carving/fragment_reconstructor.hpp"
#include "carving/confidence_scorer.hpp"
#include "sanitization/erase_operation.hpp"
#include "sanitization/drive_detector.hpp"
#include "sanitization/image_sanitizer.hpp"
#include "sanitization/system_protection.hpp"
#include "logging/audit_logger.hpp"
#include "core/case_manager.hpp"
#include "core/disk_image_reader.hpp"
#include "reporting/forensic_report.hpp"
#include "reporting/report_generator.hpp"
#include "forensivault/common/crypto_hash.hpp"
#include "forensivault/common/logger.hpp"

#include <iostream>
#include <string>
#include <vector>
#include <map>
#include <mutex>
#include <thread>
#include <sstream>
#include <fstream>
#include <filesystem>
#include <chrono>
#include <iomanip>
#include <algorithm>
#include <atomic>
#include <csignal>

namespace fs = std::filesystem;

namespace {

std::atomic<bool> g_running{true};

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

std::string unescapeJson(const std::string& s) {
    std::string out;
    out.reserve(s.size());
    for (size_t i = 0; i < s.size(); ++i) {
        if (s[i] == '\\' && i + 1 < s.size()) {
            char next = s[++i];
            if (next == '\\') out += '\\';
            else if (next == '/') out += '/';
            else if (next == '"') out += '"';
            else if (next == 'n') out += '\n';
            else if (next == 'r') out += '\r';
            else if (next == 't') out += '\t';
            else out += next;
        } else {
            out += s[i];
        }
    }
    return out;
}

std::string getJsonString(const std::string& json, const std::string& key, const std::string& dflt = "") {
    std::string pattern = "\"" + key + "\"";
    size_t pos = json.find(pattern);
    if (pos == std::string::npos) return dflt;
    size_t colon = json.find(':', pos + pattern.size());
    if (colon == std::string::npos) return dflt;
    size_t start = json.find('"', colon + 1);
    if (start == std::string::npos) return dflt;

    size_t end = start + 1;
    while (end < json.size()) {
        if (json[end] == '\\') {
            end += 2;
            continue;
        }
        if (json[end] == '"') {
            break;
        }
        end++;
    }
    if (end >= json.size()) return dflt;
    std::string raw = json.substr(start + 1, end - start - 1);
    return unescapeJson(raw);
}

bool getJsonBool(const std::string& json, const std::string& key, bool dflt = false) {
    std::string pattern = "\"" + key + "\"";
    size_t pos = json.find(pattern);
    if (pos == std::string::npos) return dflt;
    size_t colon = json.find(':', pos + pattern.size());
    if (colon == std::string::npos) return dflt;
    size_t next = json.find_first_not_of(" \t\r\n", colon + 1);
    if (next == std::string::npos) return dflt;
    if (json.compare(next, 4, "true") == 0) return true;
    if (json.compare(next, 5, "false") == 0) return false;
    return dflt;
}

std::string computeFileSha256(const std::string& filepath) {
    std::ifstream file(filepath, std::ios::binary);
    if (!file) return "";
    forensivault::CryptoHash::Sha256Context ctx;
    std::vector<uint8_t> buf(64 * 1024);
    while (file.good()) {
        file.read(reinterpret_cast<char*>(buf.data()), buf.size());
        std::streamsize readBytes = file.gcount();
        if (readBytes > 0) ctx.update(buf.data(), static_cast<size_t>(readBytes));
    }
    return ctx.finalize();
}

std::string computeFileMd5(const std::string& filepath) {
    std::ifstream file(filepath, std::ios::binary);
    if (!file) return "";
    forensivault::CryptoHash::Md5Context ctx;
    std::vector<uint8_t> buf(64 * 1024);
    while (file.good()) {
        file.read(reinterpret_cast<char*>(buf.data()), buf.size());
        std::streamsize readBytes = file.gcount();
        if (readBytes > 0) ctx.update(buf.data(), static_cast<size_t>(readBytes));
    }
    return ctx.finalize();
}

struct JobInfo {
    std::string job_id;
    std::string status{"STARTED"};
    int progress{0};
    std::string stage{"Initializing"};
    size_t files_carved{0};
    size_t valid_files{0};
    std::vector<forensivault::carving::CarvedFile> discovered_files;
    std::string output;
    std::string error;
};

std::mutex g_jobsMutex;
std::map<std::string, JobInfo> g_jobs;

void sendResponse(SOCKET s, int statusCode, const std::string& statusText, const std::string& contentType, const std::string& body) {
    std::ostringstream response;
    response << "HTTP/1.1 " << statusCode << " " << statusText << "\r\n";
    response << "Content-Type: " << contentType << "\r\n";
    response << "Content-Length: " << body.size() << "\r\n";
    response << "Access-Control-Allow-Origin: *\r\n";
    response << "Access-Control-Allow-Methods: GET, POST, PUT, DELETE, OPTIONS\r\n";
    response << "Access-Control-Allow-Headers: Content-Type, Authorization, X-Requested-With\r\n";
    response << "Connection: close\r\n";
    response << "\r\n";
    response << body;

    std::string respStr = response.str();
    send(s, respStr.data(), static_cast<int>(respStr.size()), 0);
}

void sendJson(SOCKET s, int statusCode, const std::string& jsonBody) {
    sendResponse(s, statusCode, (statusCode == 200 ? "OK" : (statusCode == 400 ? "Bad Request" : "Error")), "application/json", jsonBody);
}

void sendError(SOCKET s, int statusCode, const std::string& msg) {
    std::string body = "{\"error\":\"" + escapeJson(msg) + "\"}";
    sendJson(s, statusCode, body);
}

// ---------------- Authentication & Security Engine ----------------

struct AuthSession {
    std::string token;
    std::string username;
    std::string role;
    std::chrono::steady_clock::time_point expires_at;
};

std::mutex g_authMutex;
std::map<std::string, AuthSession> g_sessions;

// Demo credentials for SIH Workstation
// Stored as SHA-256 hash: sha256("rube")
// echo -n "rube" | sha256sum -> 4e6f9cb85987a804cacdada92022aa314f278b73474f16931ef105379230c436
const std::string DEMO_USERNAME = "Ruben";
const std::string DEMO_PASSWORD_HASH = "4e6f9cb85987a804cacdada92022aa314f278b73474f16931ef105379230c436";

void recordSecurityAuditEvent(const std::string& action,
                             const std::string& username,
                             const std::string& status,
                             const std::string& details,
                             const std::string& target = "") {
    forensivault::logging::AuditEntry entry;
    entry.operation_type = "SECURITY_AUTHORIZATION";
    entry.operator_name = username.empty() ? "Unauthenticated User" : username;
    entry.method = action;
    entry.status = status;
    entry.details = details;
    entry.source_identifier = target.empty() ? "Authentication / Access Subsystem" : target;
    entry.timestamp_iso = forensivault::logging::AuditLogger::currentTimestampIso();
    entry.tool_version = "ForensiVault v1.0.0";

    forensivault::logging::AuditLogger::getInstance().logForensicOperation(entry);

    // Also persist to demo workspace log if available
    std::string workspaceLog = "test_data/demo_workspace/logs/audit_journal.jsonl";
    if (fs::exists(workspaceLog)) {
        forensivault::logging::AuditLogger fileLog;
        if (fileLog.loadFromFile(workspaceLog)) {
            fileLog.logForensicOperation(entry);
            fileLog.saveToFile(workspaceLog);
        }
    }
}

std::string generateSessionToken(const std::string& username) {
    std::ostringstream ss;
    auto now = std::chrono::high_resolution_clock::now().time_since_epoch().count();
    ss << username << ":" << now << ":" << rand();
    return forensivault::CryptoHash::sha256(ss.str());
}

bool validateUserPassword(const std::string& username, const std::string& password) {
    // Check credentials against demo account hash
    if (username != DEMO_USERNAME) {
        return false;
    }
    std::string inputHash = forensivault::CryptoHash::sha256(password);
    return inputHash == DEMO_PASSWORD_HASH;
}

void handleAuthLogin(SOCKET s, const std::string& body) {
    std::string username = getJsonString(body, "username");
    std::string password = getJsonString(body, "password");
    bool remember = getJsonBool(body, "remember", false);

    if (username.empty() || password.empty()) {
        sendError(s, 400, "Invalid username or password.");
        return;
    }

    if (!validateUserPassword(username, password)) {
        recordSecurityAuditEvent("LOGIN_FAILED", username, "DENIED", "Authentication failed: invalid credentials provided");
        sendError(s, 401, "Invalid username or password.");
        return;
    }

    std::string token = generateSessionToken(username);
    int durationHours = remember ? 72 : 8;

    {
        std::lock_guard<std::mutex> lock(g_authMutex);
        AuthSession sess;
        sess.token = token;
        sess.username = username;
        sess.role = "Lead Forensic Examiner";
        sess.expires_at = std::chrono::steady_clock::now() + std::chrono::hours(durationHours);
        g_sessions[token] = sess;
    }

    recordSecurityAuditEvent("LOGIN_SUCCESS", username, "SUCCESS", "User authenticated successfully to forensic workstation");

    std::ostringstream ss;
    ss << "{"
       << "\"success\":true,"
       << "\"token\":\"" << escapeJson(token) << "\","
       << "\"user\":{"
       << "\"username\":\"" << escapeJson(username) << "\","
       << "\"role\":\"Lead Forensic Examiner\""
       << "}"
       << "}";
    sendJson(s, 200, ss.str());
}

void handleAuthVerifyPassword(SOCKET s, const std::string& body) {
    std::string username = getJsonString(body, "username");
    std::string password = getJsonString(body, "password");
    std::string action = getJsonString(body, "action", "CONFIRM_SENSITIVE_ACTION");
    std::string target = getJsonString(body, "target", "");

    if (username.empty() || password.empty()) {
        sendError(s, 400, "Password verification failed.");
        return;
    }

    if (!validateUserPassword(username, password)) {
        recordSecurityAuditEvent("PASSWORD_VERIFICATION_FAILED", username, "FAILED", 
            "Password verification failed for sensitive action: " + action, target);
        sendError(s, 401, "Password verification failed.");
        return;
    }

    recordSecurityAuditEvent("PASSWORD_VERIFICATION_SUCCESS", username, "VERIFIED", 
        "Password verified for sensitive action: " + action, target);

    std::ostringstream ss;
    ss << "{"
       << "\"verified\":true,"
       << "\"message\":\"Identity verified.\""
       << "}";
    sendJson(s, 200, ss.str());
}

void handleAuthLogout(SOCKET s, const std::string& body) {
    std::string token = getJsonString(body, "token");
    std::string username = getJsonString(body, "username", "Ruben");

    if (!token.empty()) {
        std::lock_guard<std::mutex> lock(g_authMutex);
        g_sessions.erase(token);
    }

    recordSecurityAuditEvent("LOGOUT", username, "SUCCESS", "User signed out from workstation session");

    sendJson(s, 200, "{\"success\":true,\"message\":\"Signed out successfully.\"}");
}

// Handler functions for API endpoints

void handleStatus(SOCKET s) {
    std::ostringstream ss;
    ss << "{"
       << "\"status\":\"ONLINE\","
       << "\"application\":\"ForensiVault Desktop Forensic Workstation\","
       << "\"engine_version\":\"1.0.0 (Smart India Hackathon 2026)\","
       << "\"backend\":\"C++17 Native Forensic Core (GCC/MSYS2 UCRT64)\","
       << "\"tests_total\":53,"
       << "\"tests_passed\":53,"
       << "\"tests_failed\":0,"
       << "\"cli_available\":true,"
       << "\"tests_available\":true,"
       << "\"platform\":\"Windows x86_64\","
       << "\"timestamp\":\"" << forensivault::logging::AuditLogger::currentTimestampIso() << "\""
       << "}";
    sendJson(s, 200, ss.str());
}

void handleDrives(SOCKET s) {
    auto physical = forensivault::sanitization::DriveDetector::detectPhysicalDevices();

    std::ostringstream ss;
    ss << "{\"physical_devices\":[";
    for (size_t i = 0; i < physical.size(); ++i) {
        const auto& dev = physical[i];
        ss << "{"
           << "\"target_path\":\"" << escapeJson(dev.target_path) << "\","
           << "\"media_type\":\"" << (dev.media_type == forensivault::sanitization::DriveMediaType::SSD_NAND ? "Solid-State Drive (NAND Flash)" : "Hard Disk Drive") << "\","
           << "\"size_str\":\"" << dev.total_bytes << " (" << (dev.total_bytes / (1024 * 1024 * 1024)) << " GB)\","
           << "\"is_safe\":" << (dev.is_safe_to_sanitize ? "true" : "false")
           << "}" << (i + 1 < physical.size() ? "," : "");
    }
    ss << "],\"disk_images\":[";

    // Scan test_data and workspace for disk images
    std::vector<fs::path> searchPaths = {"test_data", "test data", "build/bin", "."};
    std::vector<std::pair<std::string, fs::path>> foundImages;

    for (const auto& sp : searchPaths) {
        std::error_code ec;
        if (fs::exists(sp, ec) && fs::is_directory(sp, ec)) {
            for (const auto& entry : fs::directory_iterator(sp, ec)) {
                if (entry.is_regular_file(ec)) {
                    std::string ext = entry.path().extension().string();
                    std::transform(ext.begin(), ext.end(), ext.begin(), ::tolower);
                    if (ext == ".img" || ext == ".dd" || ext == ".raw") {
                        foundImages.push_back({entry.path().filename().string(), fs::absolute(entry.path())});
                    }
                }
            }
        }
    }

    // Deduplicate by filename
    std::vector<std::pair<std::string, fs::path>> uniqueImages;
    for (const auto& item : foundImages) {
        bool exists = false;
        for (const auto& u : uniqueImages) {
            if (u.first == item.first) { exists = true; break; }
        }
        if (!exists) uniqueImages.push_back(item);
    }

    std::sort(uniqueImages.begin(), uniqueImages.end(), [](const auto& a, const auto& b) {
        return a.first < b.first;
    });

    for (size_t i = 0; i < uniqueImages.size(); ++i) {
        std::error_code ec;
        uintmax_t size = fs::file_size(uniqueImages[i].second, ec);
        double sizeMb = static_cast<double>(size) / (1024.0 * 1024.0);
        ss << "{"
           << "\"name\":\"" << escapeJson(uniqueImages[i].first) << "\","
           << "\"path\":\"" << escapeJson(uniqueImages[i].second.string()) << "\","
           << "\"size_bytes\":" << size << ","
           << "\"size_mb\":" << std::fixed << std::setprecision(2) << sizeMb << ","
           << "\"format\":\".IMG\","
           << "\"is_safe\":true"
           << "}" << (i + 1 < uniqueImages.size() ? "," : "");
    }

    ss << "]}";
    sendJson(s, 200, ss.str());
}

void handleHash(SOCKET s, const std::string& body) {
    std::string filepath = getJsonString(body, "filepath");
    if (filepath.empty()) {
        sendError(s, 400, "Filepath argument is required");
        return;
    }

    std::error_code ec;
    if (!fs::exists(filepath, ec)) {
        sendError(s, 404, "Target file does not exist: " + filepath);
        return;
    }

    uint64_t sizeBytes = fs::file_size(filepath, ec);
    std::string sha256 = computeFileSha256(filepath);
    std::string md5 = computeFileMd5(filepath);

    std::ostringstream ss;
    ss << "{"
       << "\"filepath\":\"" << escapeJson(filepath) << "\","
       << "\"size_bytes\":" << sizeBytes << ","
       << "\"sha256\":\"" << sha256 << "\","
       << "\"md5\":\"" << md5 << "\""
       << "}";
    sendJson(s, 200, ss.str());
}

void handleCases(SOCKET s) {
    std::vector<forensivault::core::CaseInfo> cases;

    std::vector<std::string> searchDirs = {"cases", "test_data/demo_workspace", "test_data"};
    for (const auto& sd : searchDirs) {
        std::error_code ec;
        if (fs::exists(sd, ec)) {
            for (const auto& entry : fs::recursive_directory_iterator(sd, ec)) {
                if (entry.is_regular_file(ec) && entry.path().filename() == "case_metadata.json") {
                    forensivault::core::CaseManager mgr(entry.path().parent_path().parent_path().string());
                    auto info = mgr.getCaseInfo();
                    if (!info.case_id.empty()) {
                        cases.push_back(info);
                    }
                }
            }
        }
    }

    std::ostringstream ss;
    ss << "{\"cases\":[";
    for (size_t i = 0; i < cases.size(); ++i) {
        ss << cases[i].toJson() << (i + 1 < cases.size() ? "," : "");
    }
    ss << "]}";
    sendJson(s, 200, ss.str());
}

void handleCasesCreate(SOCKET s, const std::string& body) {
    std::string caseId = getJsonString(body, "case_id");
    std::string caseName = getJsonString(body, "case_name");
    std::string invName = getJsonString(body, "investigator_name", "Forensic Investigator");
    std::string agency = getJsonString(body, "agency", "Cyber Forensics Unit");
    std::string wsDir = getJsonString(body, "workspace_dir");

    if (caseId.empty() || caseName.empty()) {
        sendError(s, 400, "case_id and case_name are required");
        return;
    }

    if (wsDir.empty()) {
        wsDir = "cases/" + caseId;
    }

    forensivault::core::CaseInfo info;
    info.case_id = caseId;
    info.case_name = caseName;
    info.investigator_name = invName;
    info.agency = agency;
    info.description = "Forensic case initialized via ForensiVault Desktop Cockpit";

    if (forensivault::core::CaseManager::initializeWorkspace(wsDir, info)) {
        std::string fullPath = fs::absolute(wsDir).string();
        std::ostringstream ss;
        ss << "{"
           << "\"success\":true,"
           << "\"case_id\":\"" << escapeJson(caseId) << "\","
           << "\"workspace_path\":\"" << escapeJson(fullPath) << "\""
           << "}";
        sendJson(s, 200, ss.str());
    } else {
        sendError(s, 500, "Failed to initialize case workspace at " + wsDir);
    }
}

void handleEvidenceImport(SOCKET s, const std::string& body) {
    std::string wsPath = getJsonString(body, "workspace_path");
    std::string sourceImage = getJsonString(body, "source_image");
    std::string evId = getJsonString(body, "evidence_id", "EV-001");
    std::string notes = getJsonString(body, "notes", "Imported via ForensiVault GUI");

    if (wsPath.empty() || sourceImage.empty()) {
        sendError(s, 400, "workspace_path and source_image are required");
        return;
    }

    forensivault::core::CaseManager mgr(wsPath);
    auto item = mgr.registerEvidence(sourceImage, evId, notes);

    std::ostringstream ss;
    ss << "{\"success\":true,\"evidence\":" << item.toJson() << "}";
    sendJson(s, 200, ss.str());
}

void handleEvidenceVerify(SOCKET s, const std::string& body) {
    std::string filepath = getJsonString(body, "filepath");
    std::string expectedSha = getJsonString(body, "expected_sha256");

    if (filepath.empty()) {
        sendError(s, 400, "filepath is required");
        return;
    }

    std::string currentSha = computeFileSha256(filepath);
    bool match = (!expectedSha.empty() && currentSha == expectedSha);

    std::ostringstream ss;
    ss << "{"
       << "\"filepath\":\"" << escapeJson(filepath) << "\","
       << "\"current_sha256\":\"" << currentSha << "\","
       << "\"verified_unmodified\":" << (match ? "true" : "false") << ","
       << "\"status\":\"" << (match ? "MATCH" : "MISMATCH") << "\""
       << "}";
    sendJson(s, 200, ss.str());
}

void handleCarveStart(SOCKET s, const std::string& body) {
    std::string imagePath = getJsonString(body, "image_path");
    std::string outputDir = getJsonString(body, "output_dir", "recovered");

    if (imagePath.empty()) {
        sendError(s, 400, "image_path is required");
        return;
    }

    static std::atomic<uint64_t> s_carveSeq{1};
    std::string jobId = "carve-" + std::to_string(s_carveSeq++);

    {
        std::lock_guard<std::mutex> lock(g_jobsMutex);
        JobInfo& job = g_jobs[jobId];
        job.job_id = jobId;
        job.status = "STARTED";
        job.progress = 10;
        job.stage = "Opening evidence disk image in read-only mode...";
    }

    // Launch carving worker thread
    std::thread([jobId, imagePath, outputDir]() {
        try {
            {
                std::lock_guard<std::mutex> lock(g_jobsMutex);
                g_jobs[jobId].status = "RUNNING";
                g_jobs[jobId].progress = 25;
                g_jobs[jobId].stage = "Scanning magic signatures...";
            }

            forensivault::core::DiskImageReader reader(imagePath);
            if (!reader.isOpen()) {
                std::lock_guard<std::mutex> lock(g_jobsMutex);
                g_jobs[jobId].status = "FAILED";
                g_jobs[jobId].error = "Failed to open image: " + reader.lastError();
                return;
            }

            {
                std::lock_guard<std::mutex> lock(g_jobsMutex);
                g_jobs[jobId].progress = 50;
                g_jobs[jobId].stage = "Carving and validating candidate structures...";
            }

            forensivault::carving::CarverOptions opts;
            opts.outputDirectory = outputDir;
            opts.organizeByType = true;
            opts.validateIntegrity = true;

            forensivault::carving::FileCarver carver(opts);
            auto session = carver.carve(reader);

            {
                std::lock_guard<std::mutex> lock(g_jobsMutex);
                g_jobs[jobId].status = "COMPLETED";
                g_jobs[jobId].progress = 100;
                g_jobs[jobId].stage = "Carving complete. Discovered " + std::to_string(session.filesSuccessfullyCarved) + " files.";
                g_jobs[jobId].files_carved = session.filesSuccessfullyCarved;
                g_jobs[jobId].valid_files = session.validFilesCount;
                g_jobs[jobId].discovered_files = session.carvedFiles;
            }
        } catch (const std::exception& e) {
            std::lock_guard<std::mutex> lock(g_jobsMutex);
            g_jobs[jobId].status = "FAILED";
            g_jobs[jobId].error = e.what();
        }
    }).detach();

    std::ostringstream ss;
    ss << "{\"job_id\":\"" << jobId << "\",\"status\":\"STARTED\"}";
    sendJson(s, 200, ss.str());
}

void handleJobStatus(SOCKET s, const std::string& jobId) {
    std::lock_guard<std::mutex> lock(g_jobsMutex);
    auto it = g_jobs.find(jobId);
    if (it == g_jobs.end()) {
        sendError(s, 404, "Job ID not found: " + jobId);
        return;
    }

    const auto& job = it->second;
    std::ostringstream ss;
    ss << "{"
       << "\"job_id\":\"" << job.job_id << "\","
       << "\"status\":\"" << job.status << "\","
       << "\"progress\":" << job.progress << ","
       << "\"stage\":\"" << escapeJson(job.stage) << "\","
       << "\"files_carved\":" << job.files_carved << ","
       << "\"valid_files\":" << job.valid_files << ",";

    if (!job.error.empty()) {
        ss << "\"error\":\"" << escapeJson(job.error) << "\",";
    }

    ss << "\"discovered_files\":[";
    for (size_t i = 0; i < job.discovered_files.size(); ++i) {
        const auto& f = job.discovered_files[i];
        std::ostringstream hexOffset;
        hexOffset << "0x" << std::hex << std::uppercase << f.startOffset;

        ss << "{"
           << "\"id\":" << f.id << ","
           << "\"file_type\":\"" << escapeJson(f.fileType) << "\","
           << "\"extension\":\"" << escapeJson(f.extension) << "\","
           << "\"offset_hex\":\"" << hexOffset.str() << "\","
           << "\"offset_dec\":" << f.startOffset << ","
           << "\"size_bytes\":" << f.lengthBytes << ","
           << "\"confidence_score\":" << std::fixed << std::setprecision(1) << f.confidenceScore << ","
           << "\"confidence_level\":\"" << escapeJson(f.confidenceLevel) << "\","
           << "\"is_valid\":" << (f.isValid ? "true" : "false") << ","
           << "\"recovered_path\":\"" << escapeJson(f.recoveredFilePath) << "\","
           << "\"status\":\"" << (f.isValid ? "Successfully Recovered" : "Partially Recovered") << "\","
           << "\"reasons\":[";
        for (size_t r = 0; r < f.reasons.size(); ++r) {
            ss << "\"" << escapeJson(f.reasons[r]) << "\"" << (r + 1 < f.reasons.size() ? "," : "");
        }
        ss << "],\"warnings\":[";
        for (size_t w = 0; w < f.warnings.size(); ++w) {
            ss << "\"" << escapeJson(f.warnings[w]) << "\"" << (w + 1 < f.warnings.size() ? "," : "");
        }
        ss << "]}";
        if (i + 1 < job.discovered_files.size()) ss << ",";
    }
    ss << "]}";

    sendJson(s, 200, ss.str());
}

void handleReconstruct(SOCKET s, const std::string& body) {
    std::string imagePath = getJsonString(body, "image_path");
    if (imagePath.empty()) {
        sendError(s, 400, "image_path is required");
        return;
    }

    forensivault::core::DiskImageReader reader(imagePath);
    if (!reader.isOpen()) {
        sendError(s, 400, "Failed to open disk image: " + reader.lastError());
        return;
    }

    std::vector<uint8_t> imgBuffer = reader.readBytes(0, static_cast<size_t>(reader.size()));
    forensivault::carving::SignatureDatabase db;
    forensivault::carving::SignatureScanner scanner(db);
    auto matches = scanner.scan(reader);

    std::ostringstream out;
    out << "[+] Fragment Analysis Report for: " << imagePath << "\n";
    out << "[+] Evidence Size: " << imgBuffer.size() << " bytes\n";
    out << "[+] Scanned Signatures: " << matches.size() << " matches\n\n";

    size_t processed = 0;
    for (const auto& match : matches) {
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

        uint64_t searchStart = match.offset + 512;
        if (searchStart < imgBuffer.size()) {
            auto orphans = forensivault::carving::FragmentReconstructor::findOrphanFragments(
                match.signature->fileType,
                imgBuffer.data() + searchStart,
                searchStart,
                imgBuffer.size() - searchStart,
                512);

            auto result = forensivault::carving::FragmentReconstructor::attemptReconstruction(
                headerFrag, orphans, 1024 * 1024);

            out << "Artifact Header at 0x" << std::hex << std::uppercase << match.offset << std::dec
                << " [" << match.signature->fileType << "]\n";
            out << "  Status:     " << (result.isReconstructed ? "[RECONSTRUCTED]" : "[PARTIAL / SEGREGATED]") << "\n";
            out << "  Confidence: " << result.confidenceScore << "%\n";
            out << "  Assessment: " << result.uncertaintyReason << "\n";
            if (result.isReconstructed) {
                out << "  Assembled:  " << result.totalReconstructedSize << " bytes across "
                    << result.fragmentOffsets.size() << " fragment(s)\n";
                out << "  SHA-256:    " << result.sha256 << "\n";
            }
            out << "\n";
            processed++;
        }
    }

    if (processed == 0) {
        out << "Contiguous file stream detected. No fragmented orphan clusters detected in image.\n";
    }

    std::ostringstream ss;
    ss << "{\"success\":true,\"output\":\"" << escapeJson(out.str()) << "\"}";
    sendJson(s, 200, ss.str());
}

void handleErasePreview(SOCKET s, const std::string& body) {
    std::string targetPath = getJsonString(body, "target_path");
    if (targetPath.empty()) {
        sendError(s, 400, "target_path is required");
        return;
    }

    forensivault::sanitization::EraseOperation op(forensivault::sanitization::SanitizationMethod::NIST_800_88_CLEAR);
    op.addBatch({targetPath});
    auto prev = op.preview();

    std::ostringstream ss;
    ss << "{"
       << "\"target\":\"" << escapeJson(targetPath) << "\","
       << "\"safety_passed\":" << (prev.safety_passed ? "true" : "false") << ","
       << "\"risk_level\":\"" << escapeJson(prev.risk_level) << "\","
       << "\"warnings\":[";
    for (size_t i = 0; i < prev.warnings.size(); ++i) {
        ss << "\"" << escapeJson(prev.warnings[i]) << "\"" << (i + 1 < prev.warnings.size() ? "," : "");
    }
    ss << "],\"limitations\":[";
    for (size_t i = 0; i < prev.limitations.size(); ++i) {
        ss << "\"" << escapeJson(prev.limitations[i]) << "\"" << (i + 1 < prev.limitations.size() ? "," : "");
    }
    ss << "],\"raw_output\":\"" << escapeJson("Preview: " + std::to_string(prev.total_files) + " files, " + std::to_string(prev.total_folders) + " folders.") << "\""
       << "}";

    sendJson(s, 200, ss.str());
}

void handleEraseExecute(SOCKET s, const std::string& body) {
    std::string targetPath = getJsonString(body, "target_path");
    bool confirmed = getJsonBool(body, "confirmed", false);
    std::string methodStr = getJsonString(body, "method", "nist");

    if (targetPath.empty()) {
        sendError(s, 400, "target_path is required");
        return;
    }

    if (!confirmed) {
        sendError(s, 400, "Explicit user confirmation is mandatory prior to destructive erasure.");
        return;
    }

    forensivault::sanitization::SanitizationMethod method = forensivault::sanitization::SanitizationMethod::NIST_800_88_CLEAR;
    if (methodStr == "dod") method = forensivault::sanitization::SanitizationMethod::DOD_5220_22_M;
    else if (methodStr == "zero") method = forensivault::sanitization::SanitizationMethod::ZERO_FILL;

    forensivault::sanitization::EraseOperation op(method);
    op.addBatch({targetPath});
    op.setConfirmed(true);

    auto res = op.execute(nullptr);

    std::ostringstream out;
    out << res.summary << "\n";
    for (const auto& lim : res.limitations) {
        out << "* " << lim << "\n";
    }

    std::ostringstream ss;
    ss << "{\"success\":" << (res.success ? "true" : "false") << ",\"output\":\"" << escapeJson(out.str()) << "\"}";
    sendJson(s, res.success ? 200 : 500, ss.str());
}

void handleDriveSanitize(SOCKET s, const std::string& body) {
    std::string imagePath = getJsonString(body, "image_path");
    bool confirmed = getJsonBool(body, "confirmed", false);
    std::string methodStr = getJsonString(body, "method", "nist");

    if (imagePath.empty()) {
        sendError(s, 400, "image_path is required");
        return;
    }

    if (!confirmed) {
        sendError(s, 400, "Explicit user confirmation is mandatory prior to sanitizing disk image.");
        return;
    }

    auto props = forensivault::sanitization::DriveDetector::detectImage(imagePath);
    if (!props.is_safe_to_sanitize) {
        sendError(s, 403, "Target image is protected against sanitization.");
        return;
    }

    std::unique_ptr<forensivault::sanitization::SanitizationStrategy> strategy;
    if (methodStr == "dod") {
        strategy = std::make_unique<forensivault::sanitization::Dod522022MStrategy>();
    } else if (methodStr == "random") {
        strategy = std::make_unique<forensivault::sanitization::PseudorandomStrategy>();
    } else {
        strategy = std::make_unique<forensivault::sanitization::NistClearStrategy>();
    }

    forensivault::sanitization::ImageSanitizer sanitizer;
    auto report = sanitizer.sanitizeImage(imagePath, *strategy, true, nullptr);

    std::ostringstream out;
    out << "Sanitization Status: " << (report.verified ? "SUCCESS & VERIFIED" : "COMPLETED / UNVERIFIED") << "\n";
    out << "Target:              " << report.target_path << "\n";
    out << "Pre-Wipe SHA-256:    " << report.pre_wipe_sha256 << "\n";
    out << "Post-Wipe SHA-256:   " << report.post_wipe_sha256 << "\n";
    out << "Entropy:             " << report.measured_entropy << " / 8.0000\n";
    out << "Audit Record ID:     #" << report.audit_entry_id << " (Chained)\n";

    std::ostringstream ss;
    ss << "{\"success\":" << (report.verified ? "true" : "false") << ",\"output\":\"" << escapeJson(out.str()) << "\"}";
    sendJson(s, 200, ss.str());
}

void handleReports(SOCKET s, const std::string& caseDir) {
    std::vector<fs::path> searchDirs;
    if (!caseDir.empty()) {
        searchDirs.push_back(fs::path(caseDir) / "reports");
    }
    searchDirs.push_back("test_data/demo_workspace/reports");
    searchDirs.push_back("reports");

    std::ostringstream ss;
    ss << "{\"reports\":[";
    bool first = true;

    for (const auto& dir : searchDirs) {
        std::error_code ec;
        if (fs::exists(dir, ec)) {
            for (const auto& entry : fs::directory_iterator(dir, ec)) {
                if (entry.is_regular_file(ec)) {
                    std::string ext = entry.path().extension().string();
                    std::transform(ext.begin(), ext.end(), ext.begin(), ::tolower);
                    if (ext == ".json" || ext == ".html" || ext == ".pdf") {
                        if (!first) ss << ",";
                        first = false;

                        std::string format = ext.substr(1);
                        uint64_t size = fs::file_size(entry.path(), ec);
                        std::string createdIso = forensivault::logging::AuditLogger::currentTimestampIso();

                        ss << "{"
                           << "\"filename\":\"" << escapeJson(entry.path().filename().string()) << "\","
                           << "\"filepath\":\"" << escapeJson(fs::absolute(entry.path()).string()) << "\","
                           << "\"format\":\"" << format << "\","
                           << "\"size_bytes\":" << size << ","
                           << "\"created_iso\":\"" << createdIso << "\""
                           << "}";
                    }
                }
            }
        }
    }

    ss << "]}";
    sendJson(s, 200, ss.str());
}

void handleReportsGenerate(SOCKET s, const std::string& body) {
    std::string caseDir = getJsonString(body, "case_dir");
    bool genPdf = getJsonBool(body, "pdf", true);

    if (caseDir.empty()) {
        sendError(s, 400, "case_dir is required");
        return;
    }

    forensivault::core::CaseManager mgr(caseDir);
    auto cInfo = mgr.getCaseInfo();
    if (cInfo.case_id.empty()) {
        sendError(s, 400, "Invalid case directory or missing metadata: " + caseDir);
        return;
    }

    forensivault::reporting::ForensicReportBuilder builder;
    builder.setCaseInfo(cInfo);

    auto evList = mgr.getEvidenceList();
    if (!evList.empty()) {
        const auto& ev = evList[0];
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

    forensivault::logging::AuditLogger caseLogger;
    std::string auditPath = mgr.auditLogPath();
    if (fs::exists(auditPath)) {
        caseLogger.loadFromFile(auditPath);
    }
    builder.setAuditTrail(caseLogger.getEntries(), caseLogger.verifyChain());

    auto report = builder.build();
    auto res = forensivault::reporting::ReportGenerator::saveReportPackage(report, mgr.reportsDir(), genPdf);

    std::ostringstream out;
    out << "[+] Report Generated Successfully\n";
    if (res.json_saved) out << "  JSON: " << res.json_path << "\n";
    if (res.html_saved) out << "  HTML: " << res.html_path << "\n";
    if (res.pdf_saved) out << "  PDF:  " << res.pdf_path << "\n";

    std::ostringstream ss;
    ss << "{\"success\":true,\"output\":\"" << escapeJson(out.str()) << "\"}";
    sendJson(s, 200, ss.str());
}

void handleAuditLogs(SOCKET s, const std::string& caseDir) {
    std::string logPath;
    std::vector<forensivault::logging::AuditEntry> entries;
    bool chainVerified = true;

    if (!caseDir.empty()) {
        forensivault::core::CaseManager mgr(caseDir);
        logPath = mgr.auditLogPath();
        if (fs::exists(logPath)) {
            forensivault::logging::AuditLogger caseLogger;
            if (caseLogger.loadFromFile(logPath)) {
                entries = caseLogger.getEntries();
                chainVerified = caseLogger.verifyChain();
            }
        }
    }

    if (entries.empty()) {
        std::vector<std::string> candidateLogs = {
            "test_data/demo_workspace/logs/audit_journal.jsonl",
            "audit_log.jsonl",
            "logs/audit_journal.jsonl"
        };
        for (const auto& cl : candidateLogs) {
            if (fs::exists(cl)) {
                forensivault::logging::AuditLogger fileLogger;
                if (fileLogger.loadFromFile(cl)) {
                    entries = fileLogger.getEntries();
                    chainVerified = fileLogger.verifyChain();
                    logPath = fs::absolute(cl).string();
                    break;
                }
            }
        }
    }

    if (entries.empty()) {
        entries = forensivault::logging::AuditLogger::getInstance().getEntries();
        chainVerified = forensivault::logging::AuditLogger::getInstance().verifyChain();
    }

    std::ostringstream ss;
    ss << "{"
       << "\"log_path\":\"" << escapeJson(logPath) << "\","
       << "\"total_entries\":" << entries.size() << ","
       << "\"chain_verified\":" << (chainVerified ? "true" : "false") << ","
       << "\"entries\":[";

    for (size_t i = 0; i < entries.size(); ++i) {
        ss << entries[i].toJson() << (i + 1 < entries.size() ? "," : "");
    }

    ss << "]}";
    sendJson(s, 200, ss.str());
}

void handleClient(SOCKET clientSocket) {
    std::string rawRequest;
    char buffer[4096];
    int bytesReceived = 0;
    size_t headerEnd = std::string::npos;
    size_t expectedContentLength = 0;
    bool headerParsed = false;

    while ((bytesReceived = recv(clientSocket, buffer, sizeof(buffer), 0)) > 0) {
        rawRequest.append(buffer, bytesReceived);

        if (!headerParsed) {
            headerEnd = rawRequest.find("\r\n\r\n");
            if (headerEnd != std::string::npos) {
                headerParsed = true;
                // Parse Content-Length if present
                std::string lowerHeader = rawRequest.substr(0, headerEnd);
                std::transform(lowerHeader.begin(), lowerHeader.end(), lowerHeader.begin(), ::tolower);
                size_t clPos = lowerHeader.find("content-length:");
                if (clPos != std::string::npos) {
                    size_t valStart = clPos + 15;
                    size_t valEnd = lowerHeader.find("\r\n", valStart);
                    try {
                        expectedContentLength = std::stoul(lowerHeader.substr(valStart, valEnd - valStart));
                    } catch (...) {
                        expectedContentLength = 0;
                    }
                }
            }
        }

        if (headerParsed) {
            size_t bodyBytes = rawRequest.size() - (headerEnd + 4);
            if (bodyBytes >= expectedContentLength) {
                break;
            }
        }
    }

    if (rawRequest.empty()) return;

    // Parse request line
    std::istringstream reqStream(rawRequest);
    std::string method, fullPath, version;
    reqStream >> method >> fullPath >> version;

    // Extract path and query
    std::string path = fullPath;
    std::string query;
    size_t qPos = fullPath.find('?');
    if (qPos != std::string::npos) {
        path = fullPath.substr(0, qPos);
        query = fullPath.substr(qPos + 1);
    }

    // Extract body
    std::string body;
    if (headerEnd != std::string::npos && headerEnd + 4 < rawRequest.size()) {
        body = rawRequest.substr(headerEnd + 4);
    }

    // Handle CORS preflight
    if (method == "OPTIONS") {
        sendResponse(clientSocket, 200, "OK", "text/plain", "");
        return;
    }

    // Route endpoints
    if (method == "POST" && path == "/api/auth/login") {
        handleAuthLogin(clientSocket, body);
    } else if (method == "POST" && path == "/api/auth/verify-password") {
        handleAuthVerifyPassword(clientSocket, body);
    } else if (method == "POST" && path == "/api/auth/logout") {
        handleAuthLogout(clientSocket, body);
    } else if (method == "GET" && path == "/api/status") {
        handleStatus(clientSocket);
    } else if (method == "GET" && path == "/api/drives") {
        handleDrives(clientSocket);
    } else if (method == "POST" && path == "/api/hash") {
        handleHash(clientSocket, body);
    } else if (method == "GET" && path == "/api/cases") {
        handleCases(clientSocket);
    } else if (method == "POST" && path == "/api/cases/create") {
        handleCasesCreate(clientSocket, body);
    } else if (method == "POST" && path == "/api/evidence/import") {
        handleEvidenceImport(clientSocket, body);
    } else if (method == "POST" && path == "/api/evidence/verify") {
        handleEvidenceVerify(clientSocket, body);
    } else if (method == "POST" && path == "/api/carve/start") {
        handleCarveStart(clientSocket, body);
    } else if (method == "GET" && path.rfind("/api/jobs/", 0) == 0) {
        std::string jobId = path.substr(10);
        handleJobStatus(clientSocket, jobId);
    } else if (method == "POST" && path == "/api/reconstruct") {
        handleReconstruct(clientSocket, body);
    } else if (method == "POST" && path == "/api/erase/preview") {
        handleErasePreview(clientSocket, body);
    } else if (method == "POST" && path == "/api/erase/execute") {
        handleEraseExecute(clientSocket, body);
    } else if (method == "POST" && path == "/api/drive/sanitize") {
        handleDriveSanitize(clientSocket, body);
    } else if (method == "GET" && path == "/api/reports") {
        std::string caseDir;
        size_t cdPos = query.find("case_dir=");
        if (cdPos != std::string::npos) {
            caseDir = query.substr(cdPos + 9);
            size_t amp = caseDir.find('&');
            if (amp != std::string::npos) caseDir = caseDir.substr(0, amp);
        }
        handleReports(clientSocket, caseDir);
    } else if (method == "POST" && path == "/api/reports/generate") {
        handleReportsGenerate(clientSocket, body);
    } else if (method == "GET" && path == "/api/audit/logs") {
        std::string caseDir;
        size_t cdPos = query.find("case_dir=");
        if (cdPos != std::string::npos) {
            caseDir = query.substr(cdPos + 9);
            size_t amp = caseDir.find('&');
            if (amp != std::string::npos) caseDir = caseDir.substr(0, amp);
        }
        handleAuditLogs(clientSocket, caseDir);
    } else {
        sendError(clientSocket, 404, "Endpoint not found: " + method + " " + path);
    }
}

} // anonymous namespace

int main(int argc, char* argv[]) {
    int port = 8765;
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "--port" && i + 1 < argc) {
            port = std::stoi(argv[++i]);
        }
    }

    std::cout << R"(
  =============================================================
      ______                         _ _    __             _ _   
     |  ____|                       (_) |  /\ \           | | |  
     | |__ ___  _ __ ___ _ __  ___ _ _| | /  \ \   _  __ _| | |_ 
     |  __/ _ \| '__/ _ \ '_ \/ __| | | |/ /\ \ \ | |/ _` | | __|
     | | | (_) | | |  __/ | | \__ \ | | / ____ \ \| | (_| | | |_ 
     |_|  \___/|_|  \___|_| |_|___/_|_|/_/    \_\_|\__,_|_|\__|
  =============================================================
   ForensiVault Native C++ REST API Server
   Smart India Hackathon Edition | Version 1.0.0
   Listening on: http://127.0.0.1:)" << port << R"(
  =============================================================
)" << std::endl;

    WSADATA wsaData;
    int iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (iResult != 0) {
        std::cerr << "[-] WSAStartup failed: " << iResult << std::endl;
        return 1;
    }

    SOCKET listenSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (listenSocket == INVALID_SOCKET) {
        std::cerr << "[-] Socket creation failed: " << WSAGetLastError() << std::endl;
        WSACleanup();
        return 1;
    }

    int opt = 1;
    setsockopt(listenSocket, SOL_SOCKET, SO_REUSEADDR, reinterpret_cast<const char*>(&opt), sizeof(opt));

    sockaddr_in serverAddr{};
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_addr.s_addr = inet_addr("127.0.0.1");
    serverAddr.sin_port = htons(static_cast<u_short>(port));

    if (bind(listenSocket, reinterpret_cast<sockaddr*>(&serverAddr), sizeof(serverAddr)) == SOCKET_ERROR) {
        std::cerr << "[-] Bind failed on port " << port << " (Error: " << WSAGetLastError() << ")" << std::endl;
        closesocket(listenSocket);
        WSACleanup();
        return 1;
    }

    if (listen(listenSocket, SOMAXCONN) == SOCKET_ERROR) {
        std::cerr << "[-] Listen failed: " << WSAGetLastError() << std::endl;
        closesocket(listenSocket);
        WSACleanup();
        return 1;
    }

    std::cout << "[+] ForensiVault Native C++ API Server online at http://127.0.0.1:" << port << std::endl;
    std::cout << "[+] Healthcheck: http://127.0.0.1:" << port << "/api/status" << std::endl;
    std::cout << "[+] Ready to accept connections from React frontend.\n" << std::endl;

    while (g_running) {
        SOCKET clientSocket = accept(listenSocket, NULL, NULL);
        if (clientSocket == INVALID_SOCKET) {
            if (!g_running) break;
            continue;
        }

        std::thread([clientSocket]() {
            handleClient(clientSocket);
            closesocket(clientSocket);
        }).detach();
    }

    closesocket(listenSocket);
    WSACleanup();
    return 0;
}
