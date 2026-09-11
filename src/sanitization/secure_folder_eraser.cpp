#include "sanitization/secure_folder_eraser.hpp"
#include "sanitization/system_protection.hpp"
#include "logging/audit_logger.hpp"
#include <filesystem>
#include <algorithm>

namespace fs = std::filesystem;

namespace forensivault {
namespace sanitization {

FolderEraseReport SecureFolderEraser::eraseFolder(
    const std::string& folderPath,
    SanitizationMethod method,
    ProgressCallback callback) {

    FolderEraseReport report;
    report.folder_path = folderPath;
    report.limitations = getMethodLimitations(method);

    // 1. Safety check
    std::string blockReason;
    if (SystemProtectionGuard::isProtected(folderPath, blockReason)) {
        report.success = false;
        report.details = "SECURITY INTERLOCK BLOCKED: " + blockReason;
        logging::AuditLogger::getInstance().logEvent(
            "SAFETY_BLOCK", folderPath, getMethodDescription(method), "BLOCKED", report.details);
        return report;
    }

    std::error_code ec;
    if (!fs::exists(folderPath, ec) || !fs::is_directory(folderPath, ec)) {
        report.success = false;
        report.details = "Folder does not exist or is not a directory.";
        return report;
    }

    // 2. Discover all files and subdirectories
    std::vector<std::string> allFiles;
    std::vector<std::string> allDirs;
    uint64_t totalBytesAll = 0;

    for (const auto& entry : fs::recursive_directory_iterator(folderPath, fs::directory_options::skip_permission_denied, ec)) {
        if (entry.is_regular_file()) {
            allFiles.push_back(entry.path().string());
            totalBytesAll += entry.file_size();
        } else if (entry.is_directory()) {
            allDirs.push_back(entry.path().string());
        }
    }

    // Sort directories by depth (deepest first)
    std::sort(allDirs.begin(), allDirs.end(), [](const std::string& a, const std::string& b) {
        return a.length() > b.length();
    });

    uint64_t bytesProcessedSoFar = 0;
    size_t fileIdx = 0;

    // 3. Erase each file
    for (const auto& filePath : allFiles) {
        fileIdx++;
        uint64_t curFileSize = 0;
        try { curFileSize = fs::file_size(filePath); } catch (...) {}

        auto wrappedCb = [&](const EraseProgress& p) {
            if (callback) {
                EraseProgress agg = p;
                agg.current_file_index = fileIdx;
                agg.total_files = allFiles.size();
                agg.total_bytes_processed = bytesProcessedSoFar + p.bytes_processed_file;
                agg.total_bytes_all = totalBytesAll;
                agg.percentage = (totalBytesAll == 0) ? 100.0 :
                    (static_cast<double>(agg.total_bytes_processed) / totalBytesAll) * 100.0;
                callback(agg);
            }
        };

        auto res = file_eraser_.eraseFile(filePath, method, wrappedCb);
        report.file_verifications.push_back(res);

        if (res.is_verified) {
            report.files_erased++;
            report.total_bytes_erased += curFileSize;
            bytesProcessedSoFar += curFileSize;
        }
    }

    // 4. Remove subdirectories from deepest to shallowest
    for (const auto& dirPath : allDirs) {
        std::error_code rmEc;
        if (fs::remove(dirPath, rmEc)) {
            report.folders_removed++;
        }
    }

    // 5. Remove root directory
    std::error_code rootEc;
    if (fs::remove(folderPath, rootEc)) {
        report.folders_removed++;
        report.success = true;
        report.details = "Folder and all internal contents securely erased and verified.";
    } else {
        report.success = (report.files_erased == allFiles.size());
        report.details = "Files erased, but root folder removal encountered error: " + rootEc.message();
    }

    logging::AuditLogger::getInstance().logEvent(
        "SECURE_FOLDER_ERASE",
        folderPath,
        getMethodDescription(method),
        report.success ? "SUCCESS" : "PARTIAL",
        report.details + " Erased " + std::to_string(report.files_erased) + " files, " +
            std::to_string(report.folders_removed) + " directories."
    );

    return report;
}

} // namespace sanitization
} // namespace forensivault
