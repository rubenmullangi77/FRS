#pragma once

#include <iostream>
#include <string>
#include <sstream>
#include <mutex>
#include <chrono>
#include <iomanip>

namespace forensivault {

enum class LogLevel {
    Debug,
    Info,
    Warning,
    Error,
    ForensicAudit
};

class Logger {
public:
    static Logger& getInstance() {
        static Logger instance;
        return instance;
    }

    void setLogLevel(LogLevel level) {
        std::lock_guard<std::mutex> lock(mutex_);
        currentLevel_ = level;
    }

    void log(LogLevel level, const std::string& message, const char* file = nullptr, int line = 0) {
        if (level < currentLevel_) return;

        std::lock_guard<std::mutex> lock(mutex_);
        auto now = std::chrono::system_clock::now();
        auto now_c = std::chrono::system_clock::to_time_t(now);
        auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()) % 1000;

        std::tm tm_buf{};
#if defined(_WIN32) || defined(_WIN64)
        localtime_s(&tm_buf, &now_c);
#else
        localtime_r(&now_c, &tm_buf);
#endif

        std::ostringstream ss;
        ss << std::put_time(&tm_buf, "%Y-%m-%d %H:%M:%S")
           << '.' << std::setfill('0') << std::setw(3) << ms.count()
           << " [" << levelToString(level) << "] "
           << message;

        if (file && level == LogLevel::Error) {
            ss << " (" << file << ":" << line << ")";
        }

        std::cout << colorize(level, ss.str()) << std::endl;
    }

private:
    Logger() : currentLevel_(LogLevel::Info) {}
    std::mutex mutex_;
    LogLevel currentLevel_;

    static const char* levelToString(LogLevel level) {
        switch (level) {
            case LogLevel::Debug:         return "DEBUG";
            case LogLevel::Info:          return "INFO";
            case LogLevel::Warning:       return "WARN";
            case LogLevel::Error:         return "ERROR";
            case LogLevel::ForensicAudit: return "AUDIT";
            default:                      return "UNKNOWN";
        }
    }

    static std::string colorize(LogLevel level, const std::string& text) {
        // ANSI escape codes
        switch (level) {
            case LogLevel::Debug:         return "\033[36m" + text + "\033[0m"; // Cyan
            case LogLevel::Info:          return "\033[32m" + text + "\033[0m"; // Green
            case LogLevel::Warning:       return "\033[33m" + text + "\033[0m"; // Yellow
            case LogLevel::Error:         return "\033[31m" + text + "\033[0m"; // Red
            case LogLevel::ForensicAudit: return "\033[35m" + text + "\033[0m"; // Magenta / Purple
            default:                      return text;
        }
    }
};

#define FV_LOG_DEBUG(msg) forensivault::Logger::getInstance().log(forensivault::LogLevel::Debug, (msg), __FILE__, __LINE__)
#define FV_LOG_INFO(msg)  forensivault::Logger::getInstance().log(forensivault::LogLevel::Info, (msg))
#define FV_LOG_WARN(msg)  forensivault::Logger::getInstance().log(forensivault::LogLevel::Warning, (msg), __FILE__, __LINE__)
#define FV_LOG_ERROR(msg) forensivault::Logger::getInstance().log(forensivault::LogLevel::Error, (msg), __FILE__, __LINE__)
#define FV_LOG_AUDIT(msg) forensivault::Logger::getInstance().log(forensivault::LogLevel::ForensicAudit, (msg))

} // namespace forensivault
