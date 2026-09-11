#include "sanitization/system_protection.hpp"
#include <filesystem>
#include <algorithm>
#include <cctype>

namespace fs = std::filesystem;

namespace forensivault {
namespace sanitization {

namespace {

std::string toUpper(std::string str) {
    std::transform(str.begin(), str.end(), str.begin(), [](unsigned char c) {
        return static_cast<char>(std::toupper(c));
    });
    return str;
}

std::string canonicalizeSafe(const std::string& raw) {
    try {
#ifdef _WIN32
        // Treat "C:" as a drive root for safety checks.
        if (raw.length() == 2 &&
            std::isalpha(static_cast<unsigned char>(raw[0])) &&
            raw[1] == ':') {
            return std::string(1, raw[0]) + ":\\";
        }
#endif

        fs::path p(raw);

        if (fs::exists(p)) {
            return fs::weakly_canonical(p).string();
        }

        return fs::absolute(p).lexically_normal().string();
    }
    catch (...) {
        return raw;
    }
}

} // anonymous namespace

std::string SystemProtectionGuard::normalizePath(const std::string& rawPath) {
    std::string s = canonicalizeSafe(rawPath);
    // Replace all forward slashes with backslashes for unified comparison
    std::replace(s.begin(), s.end(), '/', '\\');
    // Remove trailing backslash if not root (e.g. "C:\" -> keep "C:\", but "C:\foo\" -> "C:\foo")
    if (s.length() > 3 && s.back() == '\\') {
        s.pop_back();
    }
    return toUpper(s);
}

bool SystemProtectionGuard::isDriveRoot(const std::string& targetPath) {
    std::string norm = normalizePath(targetPath);
    if (norm == "\\" || norm == "/" || norm.empty()) {
        return true;
    }
    // Check Windows drive root: e.g. "C:", "C:\", "D:", "D:\"
    if (norm.length() == 2 && std::isalpha(static_cast<unsigned char>(norm[0])) && norm[1] == ':') {
        return true;
    }
    if (norm.length() == 3 && std::isalpha(static_cast<unsigned char>(norm[0])) && norm[1] == ':' && norm[2] == '\\') {
        return true;
    }
    return false;
}

bool SystemProtectionGuard::isProtected(const std::string& targetPath, std::string& outReason) {
    if (targetPath.empty()) {
        outReason = "Path is empty.";
        return true;
    }

    if (isDriveRoot(targetPath)) {
        outReason = "Target is a drive root directory. Drive-level root deletion is strictly prohibited.";
        return true;
    }

    std::string norm = normalizePath(targetPath);

    // List of prohibited system path prefixes
    const std::vector<std::string> systemPrefixes = {
        "\\WINDOWS",
        "\\PROGRAM FILES",
        "\\PROGRAM FILES (X86)",
        "\\PROGRAMDATA",
        "\\SYSTEM VOLUME INFORMATION",
        "\\$RECYCLE.BIN",
        "\\RECOVERY",
        "\\BOOT"
    };

    // Check against drive-qualified prefixes (e.g. "C:\WINDOWS")
    for (const auto& prefix : systemPrefixes) {
        // Drive relative: "C:\WINDOWS" or root-relative: "\WINDOWS"
        if (norm.length() >= 2 && norm[1] == ':') {
            std::string sub = norm.substr(2); // Skip "C:"
            if (sub == prefix || sub.rfind(prefix + "\\", 0) == 0) {
                outReason = "Target is an essential Windows Operating System directory (" + prefix.substr(1) + "). Erasure is strictly blocked.";
                return true;
            }
        } else if (norm == prefix || norm.rfind(prefix + "\\", 0) == 0) {
            outReason = "Target is an essential Windows Operating System directory (" + prefix.substr(1) + "). Erasure is strictly blocked.";
            return true;
        }
    }

    // Prohibited system files
    const std::vector<std::string> prohibitedFiles = {
        "PAGEFILE.SYS",
        "HIBERFIL.SYS",
        "SWAPFILE.SYS",
        "BOOTMGR",
        "BOOTNXT",
        "NTLDR",
        "NTDETECT.COM"
    };

    std::string filename;
    try {
        filename = toUpper(fs::path(targetPath).filename().string());
    } catch (...) {
        filename = norm;
    }

    for (const auto& file : prohibitedFiles) {
        if (filename == file) {
            outReason = "Target is a critical Windows system paging or boot file (" + file + "). Erasure is strictly blocked.";
            return true;
        }
    }

    // Protect "C:\Users" root directory itself (though subfolders of users can be processed)
    if (norm.length() >= 2 && norm[1] == ':') {
        std::string sub = norm.substr(2);
        if (sub == "\\USERS" || sub == "\\USERS\\DEFAULT" || sub == "\\USERS\\PUBLIC" || sub == "\\USERS\\ALL USERS") {
            outReason = "Target is a root user profile directory (" + sub.substr(1) + "). Erasure is blocked to prevent profile corruption.";
            return true;
        }
    }

    return false;
}

bool SystemProtectionGuard::validateAll(const std::vector<std::string>& paths, std::vector<std::string>& violations) {
    violations.clear();
    for (const auto& p : paths) {
        std::string reason;
        if (isProtected(p, reason)) {
            violations.push_back(p + ": " + reason);
        }
    }
    return violations.empty();
}

} // namespace sanitization
} // namespace forensivault
