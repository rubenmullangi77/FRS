#define NOMINMAX
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <shellapi.h>
#include <iostream>
#include <string>
#include <vector>
#include <algorithm>

std::wstring toWide(const std::string& str) {
    if (str.empty()) return L"";
    int size_needed = MultiByteToWideChar(CP_UTF8, 0, &str[0], (int)str.size(), NULL, 0);
    std::wstring wstrTo(size_needed, 0);
    MultiByteToWideChar(CP_UTF8, 0, &str[0], (int)str.size(), &wstrTo[0], size_needed);
    return wstrTo;
}

std::string toUtf8(const std::wstring& wstr) {
    if (wstr.empty()) return "";
    int size_needed = WideCharToMultiByte(CP_UTF8, 0, &wstr[0], (int)wstr.size(), NULL, 0, NULL, NULL);
    std::string strTo(size_needed, 0);
    WideCharToMultiByte(CP_UTF8, 0, &wstr[0], (int)wstr.size(), &strTo[0], size_needed, NULL, NULL);
    return strTo;
}

std::string getErrorMessage(DWORD code) {
    LPWSTR msgBuf = nullptr;
    DWORD size = FormatMessageW(
        FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
        NULL, code, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPWSTR)&msgBuf, 0, NULL
    );
    std::string message = "Unknown error";
    if (size && msgBuf) {
        int utf8Len = WideCharToMultiByte(CP_UTF8, 0, msgBuf, size, NULL, 0, NULL, NULL);
        if (utf8Len > 0) {
            message.resize(utf8Len);
            WideCharToMultiByte(CP_UTF8, 0, msgBuf, size, &message[0], utf8Len, NULL, NULL);
            while (!message.empty() && (message.back() == '\r' || message.back() == '\n' || message.back() == ' ')) {
                message.pop_back();
            }
        }
        LocalFree(msgBuf);
    }
    return message;
}

bool isProcessElevated() {
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
    return isElevated != FALSE;
}

bool endsWith(const std::string& str, const std::string& suffix) {
    if (str.length() < suffix.length()) return false;
    std::string s1 = str.substr(str.length() - suffix.length());
    std::string s2 = suffix;
    std::transform(s1.begin(), s1.end(), s1.begin(), ::tolower);
    std::transform(s2.begin(), s2.end(), s2.begin(), ::tolower);
    return s1 == s2;
}

int main(int argc, char* argv[]) {
    // 1. Diagnostic token check flag
    if (argc >= 2 && (std::string(argv[1]) == "--check-elevation" || std::string(argv[1]) == "-c")) {
        bool elevated = isProcessElevated();
        char exePath[MAX_PATH] = { 0 };
        GetModuleFileNameA(NULL, exePath, MAX_PATH);
        char currentDir[MAX_PATH] = { 0 };
        GetCurrentDirectoryA(MAX_PATH, currentDir);

        std::cout << "{"
                  << "\"pid\":" << GetCurrentProcessId() << ","
                  << "\"is_elevated\":" << (elevated ? "true" : "false") << ","
                  << "\"executable\":\"" << exePath << "\","
                  << "\"working_directory\":\"" << currentDir << "\""
                  << "}" << std::endl;
        return elevated ? 0 : 1;
    }

    if (argc < 3) {
        std::cerr << "Usage: forensivault_elevate <target_exe_or_bat> <working_dir> [params...]" << std::endl;
        std::cerr << "       forensivault_elevate --check-elevation" << std::endl;
        return 1;
    }

    std::string targetExe = argv[1];
    std::string workDir = argv[2];

    // Build parameter string
    std::string params = "";
    for (int i = 3; i < argc; ++i) {
        if (!params.empty()) params += " ";
        std::string arg = argv[i];
        if (arg.find(' ') != std::string::npos && (arg.front() != '"' || arg.back() != '"')) {
            params += "\"" + arg + "\"";
        } else {
            params += arg;
        }
    }

    std::wstring wTarget;
    std::wstring wParams;
    std::wstring wDir = toWide(workDir);

    // If launching a .bat or .cmd script, wrap in cmd.exe /c
    if (endsWith(targetExe, ".bat") || endsWith(targetExe, ".cmd")) {
        wchar_t comSpec[MAX_PATH] = { 0 };
        DWORD len = GetEnvironmentVariableW(L"ComSpec", comSpec, MAX_PATH);
        wTarget = (len > 0) ? std::wstring(comSpec) : L"cmd.exe";

        // cmd /c ""D:\SIH\run.bat" arg1 arg2"
        std::wstring wBat = toWide(targetExe);
        if (wBat.find(L' ') != std::wstring::npos && (wBat.front() != L'"' || wBat.back() != L'"')) {
            wBat = L"\"" + wBat + L"\"";
        }
        std::wstring wInner = wBat;
        if (!params.empty()) {
            wInner += L" " + toWide(params);
        }
        wParams = L"/c \"" + wInner + L"\"";
    } else {
        wTarget = toWide(targetExe);
        wParams = toWide(params);
    }

    std::cout << "[ELEVATION LAUNCH]" << std::endl;
    std::cout << "target=" << toUtf8(wTarget) << std::endl;
    std::cout << "working_directory=" << workDir << std::endl;
    std::cout << "parameters=" << toUtf8(wParams) << std::endl;
    std::cout << "verb=runas" << std::endl;

    if (wTarget.find(L'\\') != std::wstring::npos) {
        DWORD attrs = GetFileAttributesW(wTarget.c_str());
        if (attrs == INVALID_FILE_ATTRIBUTES) {
            std::cout << "[ELEVATION ERROR]" << std::endl;
            std::cout << "stage=TargetCheck" << std::endl;
            std::cout << "error_code=2" << std::endl;
            std::cout << "message=Target executable not found: " << toUtf8(wTarget) << std::endl;
            std::cout << "STATUS:LAUNCH_FAILED" << std::endl;
            std::cout << "CODE:2" << std::endl;
            return 2;
        }
    }

    SHELLEXECUTEINFOW sei = { sizeof(sei) };
    // NOTE: NEVER use SEE_MASK_FLAG_NO_UI here as it blocks the Windows UAC consent prompt!
    sei.fMask = SEE_MASK_NOCLOSEPROCESS;
    sei.hwnd = GetForegroundWindow();
    sei.lpVerb = L"runas";
    sei.lpFile = wTarget.c_str();
    sei.lpParameters = wParams.empty() ? NULL : wParams.c_str();
    sei.lpDirectory = wDir.empty() ? NULL : wDir.c_str();
    sei.nShow = SW_SHOWNORMAL;

    BOOL ok = ShellExecuteExW(&sei);
    if (!ok) {
        DWORD err = GetLastError();
        std::string errStr = getErrorMessage(err);
        if (err == ERROR_CANCELLED) { // 1223
            std::cout << "[ELEVATION CANCELLED]" << std::endl;
            std::cout << "user_cancelled=true" << std::endl;
            std::cout << "STATUS:CANCELLED" << std::endl;
            std::cout << "CODE:1223" << std::endl;
            return 1223;
        } else {
            std::cout << "[ELEVATION ERROR]" << std::endl;
            std::cout << "stage=ShellExecute" << std::endl;
            std::cout << "error_code=" << err << std::endl;
            std::cout << "message=" << errStr << std::endl;
            std::cout << "STATUS:LAUNCH_FAILED" << std::endl;
            std::cout << "CODE:" << err << std::endl;
            return (int)err;
        }
    }

    DWORD pid = 0;
    if (sei.hProcess) {
        pid = GetProcessId(sei.hProcess);
        CloseHandle(sei.hProcess);
    }

    std::cout << "[ELEVATION SUCCESS]" << std::endl;
    std::cout << "new_pid=" << pid << std::endl;
    std::cout << "is_elevated=true" << std::endl;
    std::cout << "STATUS:SUCCESS" << std::endl;
    std::cout << "PID:" << pid << std::endl;
    return 0;
}
