# run_all.ps1
# Shadow NDR Complete Startup Script
# ===================================

param(
    [switch]$NoWait = $false,
    [switch]$Debug = $false
)

$scriptPath = Split-Path -Parent $MyInvocation.MyCommand.Path
$ErrorActionPreference = "Continue"

Write-Host "`n╔════════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║          [ROCKET] Shadow NDR System - Complete Startup        ║" -ForegroundColor Cyan
Write-Host "╚════════════════════════════════════════════════════════════════╝`n" -ForegroundColor Cyan

# ========== PORT CHECK ==========
Write-Host "[CHECK] Checking for port conflicts..." -ForegroundColor Yellow
$ports = @(3001, 3000, 8081, 8082, 9090, 9091, 5432, 6379)
foreach ($port in $ports) {
    $netstat = netstat -ano 2>$null | Select-String "LISTENING" | Select-String ":$port\s"
    if ($netstat) {
        Write-Host "[!] Port $port is in use" -ForegroundColor Yellow
    }
}

# ========== KILL EXISTING PROCESSES ==========
Write-Host "`n[STOP] Killing existing processes..." -ForegroundColor Yellow
$processes = @("node", "shadow-sensor", "dotnet")
foreach ($proc in $processes) {
    $running = Get-Process $proc -ErrorAction SilentlyContinue
    if ($running) {
        Write-Host "  [+] Stopping $proc..." -NoNewline
        Stop-Process -Name $proc -Force -ErrorAction SilentlyContinue
        Start-Sleep -Milliseconds 500
        Write-Host " Done" -ForegroundColor Green
    }
}

Write-Host "`n[TIME] Waiting 3 seconds for ports to release..." -ForegroundColor Yellow
Start-Sleep -Seconds 3

# ========== 1. DOCKER CONTAINERS ==========
Write-Host "[*] Starting Docker containers (PostgreSQL, Redis)..." -ForegroundColor Cyan
Push-Location "$scriptPath\multi-tenant"

$dockerCheck = docker-compose ps 2>$null
if ($LASTEXITCODE -eq 0) {
    Write-Host "    Docker-compose detected, starting services..." -NoNewline
    docker-compose up -d 2>&1 | Out-Null
    if ($LASTEXITCODE -eq 0) {
        Write-Host " Done" -ForegroundColor Green
    } else {
        Write-Host " Failed - Docker may not be running" -ForegroundColor Yellow
    }
} else {
    Write-Host "    WARNING: Docker not available - ensure PostgreSQL and Redis are running" -ForegroundColor Yellow
}

Pop-Location

# ========== WAIT FOR SERVICES ==========
Write-Host "`n[TIME] Waiting 5 seconds for database services to initialize..." -ForegroundColor Yellow
Start-Sleep -Seconds 5

# ========== 2. BACKEND ==========
Write-Host "`n[CONFIG] Starting Backend Server (Port 3001)..." -ForegroundColor Cyan
$backendCmd = "cd '$scriptPath\multi-tenant\backend'; " + 
              "Write-Host 'INFO: Backend starting on http://localhost:3001' -ForegroundColor Green; " +
              "npm run dev 2>&1"

if ($Debug) {
    Write-Host "  -> Opening Backend in new window..." -ForegroundColor Gray
    Start-Process powershell -ArgumentList "-NoExit", "-Command", $backendCmd
} else {
    Start-Process powershell -ArgumentList "-NoExit", "-NoProfile", "-Command", $backendCmd
}
Write-Host "  (+) Backend window opened" -ForegroundColor Green

# ========== 3. FRONTEND ==========
Write-Host "`n[UI] Starting Frontend (Port 3000)..." -ForegroundColor Cyan
$frontendCmd = "cd '$scriptPath\multi-tenant\frontend'; " + 
               "Write-Host 'INFO: Frontend starting on http://localhost:3000' -ForegroundColor Green; " +
               "npm run dev 2>&1"

if ($Debug) {
    Write-Host "  -> Opening Frontend in new window..." -ForegroundColor Gray
    Start-Process powershell -ArgumentList "-NoExit", "-Command", $frontendCmd
} else {
    Start-Process powershell -ArgumentList "-NoExit", "-NoProfile", "-Command", $frontendCmd
}
Write-Host "  (+) Frontend window opened" -ForegroundColor Green

# ========== WAIT FOR BACKEND INITIALIZATION ==========
Write-Host "`n[TIME] Waiting 10 seconds for Backend to initialize..." -ForegroundColor Yellow
for ($i = 10; $i -gt 0; $i--) {
    Write-Host -NoNewline "`r  WAIT: $i seconds remaining..."
    Start-Sleep -Seconds 1
}
Write-Host "`r  (+) Backend initialization complete         " -ForegroundColor Green

# ========== 4. SENSOR ==========
Write-Host "`n[SHIELD] Starting Sensor (Packet Capture)..." -ForegroundColor Cyan

# Build sensor if not already built
if (!(Test-Path "$scriptPath\shadow-sensor\target\release\shadow-sensor.exe")) {
    Write-Host "  [*] Building sensor binary (this may take a minute)..." -ForegroundColor Yellow
    Push-Location "$scriptPath\shadow-sensor"
    cargo build --release 2>&1 | Select-String "Finished|error" | ForEach-Object {
        Write-Host "     $_" -ForegroundColor Gray
    }
    Pop-Location
}

$sensorCmd = "cd '$scriptPath\shadow-sensor'; " +
             "Write-Host 'INFO: Sensor starting on health:8082, metrics:9091' -ForegroundColor Green; " +
             "Write-Host 'INFO: Sending packets to http://localhost:3001/api/sensor/data' -ForegroundColor Green; " +
             "`$env:RUST_LOG='info,shadow_sensor=debug'; " +
             ".\target\release\shadow-sensor.exe --health-port 8082 --metrics-port 9091 2>&1"

if ($Debug) {
    Write-Host "  -> Opening Sensor in new window..." -ForegroundColor Gray
    Start-Process powershell -ArgumentList "-NoExit", "-Command", $sensorCmd -Verb RunAs -ErrorAction SilentlyContinue
} else {
    Start-Process powershell -ArgumentList "-NoExit", "-NoProfile", "-Command", $sensorCmd -Verb RunAs -ErrorAction SilentlyContinue
}
Write-Host "  (+) Sensor window opened (may require admin privileges)" -ForegroundColor Green

# ========== DISPLAY SUMMARY ==========
Write-Host "`n╔════════════════════════════════════════════════════════════════╗" -ForegroundColor Green
Write-Host "║                    OK: All Systems Started!                    ║" -ForegroundColor Green
Write-Host "╚════════════════════════════════════════════════════════════════╝`n" -ForegroundColor Green

Write-Host "URLS - Service URLs:" -ForegroundColor Cyan
Write-Host "   UI Frontend:     http://localhost:3000" -ForegroundColor White
Write-Host "   API Backend:      http://localhost:3001" -ForegroundColor White
Write-Host "   HEALTH Check:       http://localhost:8082" -ForegroundColor White
Write-Host "   METRICS Stats:      http://localhost:9091" -ForegroundColor White
Write-Host "   DB PostgreSQL:   localhost:5432 (user: shadow_user)" -ForegroundColor White
Write-Host "   CACHE Redis:        localhost:6379" -ForegroundColor White

Write-Host "`nFLOW - Expected Data Flow:" -ForegroundColor Cyan
Write-Host "   1. Sensor captures network packets" -ForegroundColor White
Write-Host "   2. Sensor sends to Backend API (POST /api/sensor/data)" -ForegroundColor White
Write-Host "   3. Backend stores in PostgreSQL" -ForegroundColor White
Write-Host "   4. Frontend queries and displays threats" -ForegroundColor White

Write-Host "`nHELP - Troubleshooting:" -ForegroundColor Cyan
Write-Host "   * Port 3001 (Backend) not responding: Check 'npm run dev' window" -ForegroundColor White
Write-Host "   * Port 3000 (Frontend) not responding: Check 'npm run dev' window" -ForegroundColor White
Write-Host "   * Sensor errors: Check sensor window, look for protocol/format issues" -ForegroundColor White
Write-Host "   * Docker containers not starting: Check Docker Desktop is running" -ForegroundColor White
Write-Host "   * Need admin for sensor: Restart this script as Administrator" -ForegroundColor White

Write-Host "`nCMD - Quick Commands:" -ForegroundColor Cyan
Write-Host "   Test Backend:  curl http://localhost:3001/health" -ForegroundColor Gray
Write-Host "   View Logs:     Check each service window for debug output" -ForegroundColor Gray
Write-Host "   Stop All:      Close all service windows (Ctrl+C)" -ForegroundColor Gray

Write-Host "`nNEXT - Next Steps:" -ForegroundColor Cyan
Write-Host "   1. Open http://localhost:3000 in your browser" -ForegroundColor White
Write-Host "   2. Check Backend console for 'Received sensor data' messages" -ForegroundColor White
Write-Host "   3. Verify sensor is capturing packets (check sensor window)" -ForegroundColor White
Write-Host "   4. Query database: psql -U shadow_user -d shadow_ndr" -ForegroundColor White

if (-not $NoWait) {
    Write-Host "`n⏳ Press any key to continue monitoring..." -ForegroundColor Yellow
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
}

Write-Host ""
