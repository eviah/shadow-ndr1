@echo off
REM ============================================
REM Shadow NDR Sensor - Quick Launch Script
REM ============================================
REM This script helps verify the system is ready
REM and provides instructions for launching

setlocal enabledelayedexpansion

title Shadow NDR Sensor - Launch Helper

echo.
echo ============================================
echo   Shadow NDR Sensor - Pre-Launch Check
echo ============================================
echo.

REM Check binary
echo [*] Checking shadow-sensor binary...
if exist "C:\Users\liorh\shadow-ndr\shadow-sensor\target\release\shadow-sensor.exe" (
    echo [OK] Binary found
) else (
    echo [ERROR] Binary not found - run: cargo build --release
    pause
    exit /b 1
)

REM Check Npcap
echo [*] Checking Npcap installation...
if exist "C:\Windows\System32\wpcap.dll" (
    echo [OK] Npcap installed
) else (
    echo [WARNING] Npcap not found
    echo Download from: https://npcap.com/dist/npcap-1.81.exe
    echo Install with "WinPcap API-compatible Mode" enabled
)

REM Check Docker
echo [*] Checking Docker...
docker ps >nul 2>&1
if !errorlevel! equ 0 (
    echo [OK] Docker is running
) else (
    echo [WARNING] Docker not running - start Docker Desktop
)

echo.
echo ============================================
echo   Launch Instructions
echo ============================================
echo.
echo STEP 1 - Open 5 PowerShell Windows (admin for window 4):
echo.
echo Window 1: Database ^& Cache
echo   cd C:\Users\liorh\shadow-ndr\multi-tenant
echo   docker-compose up -d
echo.
echo Window 2: Backend API
echo   cd C:\Users\liorh\shadow-ndr\multi-tenant\backend
echo   npm run dev
echo.
echo Window 3: Frontend
echo   cd C:\Users\liorh\shadow-ndr\multi-tenant\frontend
echo   npm run dev
echo.
echo Window 4: Sensor (^!ADMIN REQUIRED^!)
echo   cd C:\Users\liorh\shadow-ndr\shadow-sensor
echo   .\target\release\shadow-sensor.exe
echo.
echo Window 5: ML Engine (Optional)
echo   cd C:\Users\liorh\shadow-ndr\shadow-ml
echo   python auto_threat_simulator.py
echo.
echo STEP 2 - Test the System:
echo   Sensor Health:  http://localhost:8081/health
echo   Frontend:       http://localhost:3000
echo   Backend API:    http://localhost:3001/api/threats
echo   Metrics:        http://localhost:9090/metrics
echo.
echo Press any key to close this window and start launching!
pause
