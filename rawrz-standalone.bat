@echo off
title RawrZ Security Platform - Standalone CLI
echo.
echo =================================================
echo RawrZ Security Platform - Complete Standalone CLI
echo =================================================
echo All 72+ Security Features - No IRC, No Network Dependencies
echo.
echo Usage: rawrz-standalone.bat [command] [arguments]
echo Example: rawrz-standalone.bat encrypt aes256 C:\Windows\calc.exe .exe
echo.

if "%1"=="" (
    echo [INFO] No command provided, showing help...
    node rawrz-standalone.js help
) else (
    echo [INFO] Executing: %*
    node rawrz-standalone.js %*
)

echo.
echo [INFO] RawrZ Security Platform execution complete.
pause
