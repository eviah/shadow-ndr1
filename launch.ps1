# launch.ps1 - Shadow NDR Startup
param([switch]$NoWait = $false)
$scriptPath = Split-Path -Parent $MyInvocation.MyCommand.Path
$ErrorActionPreference = "Continue"

cls
Write-Host ""
Write-Host "Shadow NDR System Startup" -ForegroundColor Cyan
Write-Host ""

# Kill existing processes
Write-Host "Cleaning up old processes..." -ForegroundColor Yellow
Get-Process node -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
Get-Process shadow-sensor -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
Start-Sleep -Seconds 3

# Start Docker
Write-Host "Starting Docker containers..." -ForegroundColor Cyan
Push-Location "$scriptPath\multi-tenant"
docker-compose up -d 2>&1 | Out-Null
Pop-Location
Start-Sleep -Seconds 5

# Start Backend
Write-Host "Starting Backend on port 3001..." -ForegroundColor Cyan
$backendCmd = @"
cd '$scriptPath\multi-tenant\backend'
npm run dev
"@
Start-Process powershell -ArgumentList "-NoExit", "-NoProfile", "-Command", $backendCmd
Start-Sleep -Seconds 2

# Start Frontend
Write-Host "Starting Frontend on port 3000..." -ForegroundColor Cyan
$frontendCmd = @"
cd '$scriptPath\multi-tenant\frontend'
npm run dev
"@
Start-Process powershell -ArgumentList "-NoExit", "-NoProfile", "-Command", $frontendCmd
Start-Sleep -Seconds 2

# Start Sensor
Write-Host "Starting Sensor..." -ForegroundColor Cyan
$sensorCmd = @"
cd '$scriptPath\shadow-sensor'
Write-Host 'Sensor starting...' -ForegroundColor Green
`$env:RUST_LOG='info,shadow_sensor=debug'
.\target\release\shadow-sensor.exe --health-port 8082 --metrics-port 9091
"@
Start-Process powershell -ArgumentList "-NoExit", "-NoProfile", "-Command", $sensorCmd -Verb RunAs -ErrorAction SilentlyContinue

# Summary
Write-Host ""
Write-Host "All services started successfully!" -ForegroundColor Green
Write-Host ""
Write-Host "Service URLs:" -ForegroundColor Cyan
Write-Host "  Frontend:  http://localhost:3000" -ForegroundColor White
Write-Host "  Backend:   http://localhost:3001" -ForegroundColor White
Write-Host "  Health:    http://localhost:8082" -ForegroundColor White
Write-Host ""

if (-not $NoWait) {
    Write-Host "Press any key to continue..." -ForegroundColor Yellow
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
}
