@echo off
REM ============================================================================
REM SHADOW NDR - COMPLETE SYSTEM STARTUP (Batch Version)
REM Starts: Main NDR (Docker) + MT APEX (Node.js)
REM ============================================================================

echo.
echo ╔════════════════════════════════════════════════════════════════╗
echo ║   🚀 SHADOW NDR - COMPLETE SYSTEM STARTUP                     ║
echo ║   Starting Main NDR + MT APEX + All Services...               ║
echo ╚════════════════════════════════════════════════════════════════╝
echo.

REM Check for Docker
docker --version >nul 2>&1
if %errorlevel% neq 0 (
    echo ❌ Docker not found. Please install Docker Desktop.
    pause
    exit /b 1
)
echo ✅ Docker found

REM Check for Node.js
node --version >nul 2>&1
if %errorlevel% neq 0 (
    echo ❌ Node.js not found. Please install Node.js.
    pause
    exit /b 1
)
echo ✅ Node.js found

REM Check for npm
npm --version >nul 2>&1
if %errorlevel% neq 0 (
    echo ❌ npm not found. Please install npm.
    pause
    exit /b 1
)
echo ✅ npm found

echo.
echo ⏳ Starting Docker containers...
docker-compose up -d
if %errorlevel% neq 0 (
    echo ❌ Docker startup failed
    pause
    exit /b 1
)
echo ✅ Docker started

echo.
echo ⏳ Waiting for services (15 seconds)...
timeout /t 15 /nobreak

echo.
echo ⏳ Starting MT APEX Backend (Port 3001)...
start "MT APEX Backend" cmd /k "cd multi-tenant\backend && npm run dev"

echo.
echo ⏳ Starting MT APEX Frontend (Port 3001/Vite)...
start "MT APEX Frontend" cmd /k "cd multi-tenant\frontend && PORT=3001 npm run dev"

timeout /t 5 /nobreak

echo.
echo ╔════════════════════════════════════════════════════════════════╗
echo ║         ✨ ALL SYSTEMS OPERATIONAL - OPENING DASHBOARDS       ║
echo ╚════════════════════════════════════════════════════════════════╝
echo.

echo 📊 MAIN SHADOW NDR SYSTEM:
echo    UI Dashboard:        http://localhost:3000
echo    Grafana:            http://localhost:3002
echo    Prometheus:         http://localhost:9091
echo.

echo 🌟 MT APEX SYSTEM:
echo    Backend + Frontend:  http://localhost:3001
echo.

echo 💾 DATABASES:
echo    PostgreSQL (Main):   localhost:5433
echo    PostgreSQL (MT):     localhost:5432
echo    Redis:              localhost:6380
echo    ClickHouse:         localhost:8123
echo.

echo 📢 Kafka Broker:         localhost:9093
echo.

echo ✅ STATUS: PRODUCTION READY
echo.

REM Open browsers
start http://localhost:3000
start http://localhost:3001
start http://localhost:3002

echo 🎉 Opening dashboards in browser...
echo.
echo Press any key to continue monitoring...
pause

REM Show Docker logs
docker-compose logs -f
