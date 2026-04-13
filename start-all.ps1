# Start All Shadow NDR Services
# Usage: powershell -ExecutionPolicy Bypass -File .\start-all.ps1

param(
    [switch]$NoWait = $false
)

$scriptPath = Split-Path -Parent $MyInvocation.MyCommand.Path
$ErrorActionPreference = "Continue"

Write-Host "`n======================================================================" -ForegroundColor Cyan
Write-Host "           SHADOW NDR SYSTEM - COMPLETE STARTUP" -ForegroundColor Cyan
Write-Host "======================================================================`n" -ForegroundColor Cyan

# Kill existing processes
Write-Host "[*] Cleaning up old processes..." -ForegroundColor Yellow
$processes = @("node", "shadow-sensor")
foreach ($proc in $processes) {
    $running = Get-Process $proc -ErrorAction SilentlyContinue
    if ($running) {
        Write-Host "    Stopping $proc..." -NoNewline
        Stop-Process -Name $proc -Force -ErrorAction SilentlyContinue
        Start-Sleep -Milliseconds 500
        Write-Host " Done" -ForegroundColor Green
    }
}

Write-Host "`n[*] Waiting for ports to release..." -ForegroundColor Yellow
Start-Sleep -Seconds 3

# Docker services
Write-Host "`n[*] Starting Docker services (PostgreSQL, Redis)..." -ForegroundColor Cyan
Push-Location "$scriptPath\multi-tenant"
if ((docker-compose ps 2>$null) -or (docker ps 2>$null)) {
    Write-Host "    Starting containers..." -NoNewline
    docker-compose up -d 2>&1 | Out-Null
    Write-Host " Done" -ForegroundColor Green
} else {
    Write-Host "    WARNING: Docker not available" -ForegroundColor Yellow
}
Pop-Location

Start-Sleep -Seconds 5

# Backend
Write-Host "`n[*] Starting Backend Server (Port 3001)..." -ForegroundColor Cyan
$backendCmd = "cd '$scriptPath\multi-tenant\backend'; " + 
              "Write-Host '[+] Backend starting on http://localhost:3001' -ForegroundColor Green; " +
              "npm run dev 2>&1"
Start-Process powershell -ArgumentList "-NoExit", "-NoProfile", "-Command", $backendCmd
Write-Host "    Backend window opened" -ForegroundColor Green

# Frontend
Write-Host "`n[*] Starting Frontend (Port 3000)..." -ForegroundColor Cyan
$frontendCmd = "cd '$scriptPath\multi-tenant\frontend'; " + 
               "Write-Host '[+] Frontend starting on http://localhost:3000' -ForegroundColor Green; " +
               "npm run dev 2>&1"
Start-Process powershell -ArgumentList "-NoExit", "-NoProfile", "-Command", $frontendCmd
Write-Host "    Frontend window opened" -ForegroundColor Green

# Wait for backend
Write-Host "`n[*] Waiting for Backend to initialize..." -ForegroundColor Yellow
Start-Sleep -Seconds 10

# Sensor
Write-Host "`n[*] Starting Sensor (Packet Capture)..." -ForegroundColor Cyan
if (!(Test-Path "$scriptPath\shadow-sensor\target\release\shadow-sensor.exe")) {
    Write-Host "    Building sensor binary (this may take a minute)..." -ForegroundColor Yellow
    Push-Location "$scriptPath\shadow-sensor"
    cargo build --release 2>&1 | Out-Null
    Pop-Location
}

$sensorCmd = "cd '$scriptPath\shadow-sensor'; " +
             "`$env:RUST_LOG='info,shadow_sensor=debug'; " +
             ".\target\release\shadow-sensor.exe --health-port 8082 --metrics-port 9091 2>&1"
Start-Process powershell -ArgumentList "-NoExit", "-NoProfile", "-Command", $sensorCmd -Verb RunAs -ErrorAction SilentlyContinue
Write-Host "    Sensor window opened" -ForegroundColor Green

# Summary
Write-Host "`n======================================================================" -ForegroundColor Green
Write-Host "           ALL SYSTEMS STARTED!" -ForegroundColor Green
Write-Host "======================================================================`n" -ForegroundColor Green

Write-Host "SERVICE URLS:" -ForegroundColor Cyan
Write-Host "  Frontend:    http://localhost:3000" -ForegroundColor White
Write-Host "  Backend:     http://localhost:3001" -ForegroundColor White
Write-Host "  Health:      http://localhost:8082" -ForegroundColor White
Write-Host "  Metrics:     http://localhost:9091" -ForegroundColor White
Write-Host "  PostgreSQL:  localhost:5432" -ForegroundColor White
Write-Host "  Redis:       localhost:6379" -ForegroundColor White

Write-Host "`nDATA FLOW:" -ForegroundColor Cyan
Write-Host "  1. Sensor captures network packets" -ForegroundColor White
Write-Host "  2. Sensor sends to Backend API (POST /api/sensor/data)" -ForegroundColor White
Write-Host "  3. Backend stores in PostgreSQL" -ForegroundColor White
Write-Host "  4. Frontend queries and displays threats" -ForegroundColor White

Write-Host "`nNEXT STEPS:" -ForegroundColor Cyan
Write-Host "  1. Open http://localhost:3000 in your browser" -ForegroundColor White
Write-Host "  2. Check Backend console for 'Received sensor data' messages" -ForegroundColor White
Write-Host "  3. Verify sensor is capturing packets" -ForegroundColor White
Write-Host "  4. Query database: psql -U shadow_user -d shadow_ndr" -ForegroundColor White

Write-Host "`n"
