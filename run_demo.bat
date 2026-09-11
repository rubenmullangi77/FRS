@echo off
setlocal
echo ======================================================================
echo    ForensiVault Safe Demonstration Suite (Smart India Hackathon)
echo ======================================================================

echo [1/3] Generating synthetic multi-file forensic evidence image...
python tools/generate_demo_evidence.py test_data/evidence_demo.img
if %ERRORLEVEL% NEQ 0 (
    echo [ERROR] Python script failed to generate evidence image.
    exit /b %ERRORLEVEL%
)

echo.
echo [2/3] Building latest C++ forensic engine and demonstration runner...
cmake --build build --target forensic_demo forensivault_cli
if %ERRORLEVEL% NEQ 0 (
    echo [ERROR] Build failed.
    exit /b %ERRORLEVEL%
)

echo.
echo [3/3] Executing end-to-end 12-step recovery & certified sanitization demo...
.\build\bin\forensic-demo.exe test_data/evidence_demo.img

echo.
echo Demonstration finished. View case reports at:
echo   test_data/demo_workspace/reports/
pause
