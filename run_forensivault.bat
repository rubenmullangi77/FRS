@echo off
title ForensiVault Pro - Forensic Workstation Launcher
color 0A

echo ======================================================================
echo           FORENSIVAULT FORENSIC INVESTIGATION PLATFORM
echo                Smart India Hackathon 2026 Edition
echo ======================================================================
echo.

cd /d "%~dp0"

echo [*] Checking C++ Native Engine...
if exist "build\bin\forensivault_server.exe" (
    echo [OK] ForensiVault C++ API Server found: build\bin\forensivault_server.exe
) else (
    echo [WARN] C++ Server not found in build\bin. Building using cmake...
    cmake --build build
)

echo.
echo [*] Launching Native C++ ForensiVault API Server (Port 8765)...
start "ForensiVault C++ Server" /B "build\bin\forensivault_server.exe" --port 8765

echo.
echo [*] Launching ForensiVault React Forensic Dashboard...
cd frontend
start "ForensiVault Frontend" /B npm run dev -- --host 127.0.0.1 --port 5173

echo.
echo [*] Waiting for services to initialize...
timeout /t 3 >nul

echo.
echo [*] Opening Forensic Cockpit in Web Browser...
start http://127.0.0.1:5173

echo.
echo ======================================================================
echo  ForensiVault is running!
echo  - Frontend GUI:  http://127.0.0.1:5173
echo  - Backend Bridge: http://127.0.0.1:8765/api/status
echo.
echo  Press Ctrl+C or close this window to stop the application.
echo ======================================================================

:: Keep alive
pause >nul
