@echo off
title ForensiVault Desktop Forensic Workstation
color 0F
echo =====================================================================
echo       FORENSIVAULT - Professional Digital Forensics Workstation
echo                 Smart India Hackathon 2026 Edition
echo =====================================================================
echo.

net session >nul 2>&1
if %ERRORLEVEL% EQU 0 (
    echo [+] Running with verified Windows Administrator privileges.
) else (
    echo [*] Running with Standard User privileges.
)

echo [*] Checking FastAPI backend on port 8765...

curl -s http://127.0.0.1:8765/api/status >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo [*] Starting ForensiVault Python FastAPI backend...
    start /b "" py -3 -m uvicorn backend_fastapi.main:app --host 127.0.0.1 --port 8765
    timeout /t 2 /nobreak >nul
) else (
    echo [+] ForensiVault FastAPI backend is active and online.
)

echo.
echo [*] Launching ForensiVault Desktop Application (Electron)...
echo [*] Demo Credentials: Username: Ruben  ^|  Password: rube
echo.

cd /d "%~dp0frontend"
call npx electron electron/main.cjs %*

echo.
echo [*] ForensiVault session terminated.
