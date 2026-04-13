#!/usr/bin/env powershell
# Shadow NDR Sensor - Post-Launch Testing Script

Write-Host "╔════════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║     Shadow NDR Sensor - System Health Check                    ║" -ForegroundColor Cyan
Write-Host "╚════════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
Write-Host ""

# Colors for output
$greenCheck = "✅"
$redX = "❌"
$yellowWarn = "⚠️"

# Function to test endpoint
function Test-Endpoint {
    param(
        [string]$Name,
        [string]$Url,
        [int]$Port
    )
    
    Write-Host "Testing $Name..." -ForegroundColor Yellow
    try {
        $response = Invoke-WebRequest -Uri $Url -TimeoutSec 2 -ErrorAction Stop
        if ($response.StatusCode -eq 200) {
            Write-Host "  $greenCheck $Name is running on port $Port" -ForegroundColor Green
            return $true
        } else {
            Write-Host "  $redX $Name returned status $($response.StatusCode)" -ForegroundColor Red
            return $false
        }
    } catch {
        Write-Host "  $yellowWarn $Name not responding on port $Port" -ForegroundColor Yellow
        return $false
    }
}

Write-Host ""
Write-Host "🔗 ENDPOINT TESTS" -ForegroundColor Cyan
Write-Host ""

# Test each service
$results = @()
$results += Test-Endpoint -Name "Sensor Health" -Url "http://localhost:8081/health" -Port 8081
Write-Host ""
$results += Test-Endpoint -Name "Sensor Metrics" -Url "http://localhost:9090/metrics" -Port 9090
Write-Host ""
$results += Test-Endpoint -Name "Backend API" -Url "http://localhost:3001/api/health" -Port 3001
Write-Host ""

Write-Host ""
Write-Host "🔄 PROCESS CHECK" -ForegroundColor Cyan
Write-Host ""

# Check running processes
$node = Get-Process node -ErrorAction SilentlyContinue
if ($node) {
    Write-Host "  $greenCheck Node.js (Backend/Frontend) is running" -ForegroundColor Green
} else {
    Write-Host "  $redX Node.js processes not found" -ForegroundColor Red
}

$docker = Get-Process docker -ErrorAction SilentlyContinue
if ($docker) {
    Write-Host "  $greenCheck Docker is running" -ForegroundColor Green
} else {
    Write-Host "  $yellowWarn Docker not found in process list" -ForegroundColor Yellow
}

# Check sensor process (named shadow-sensor)
$sensor = Get-Process shadow-sensor -ErrorAction SilentlyContinue
if ($sensor) {
    Write-Host "  $greenCheck Sensor process is running" -ForegroundColor Green
} else {
    Write-Host "  $yellowWarn Sensor process not found" -ForegroundColor Yellow
}

Write-Host ""
Write-Host "🐳 DOCKER CONTAINERS" -ForegroundColor Cyan
Write-Host ""

try {
    $containers = docker ps --format "table {{.Names}}\t{{.Status}}"
    if ($containers) {
        Write-Host "$greenCheck Docker containers running:" -ForegroundColor Green
        $containers | ForEach-Object { Write-Host "  • $_" -ForegroundColor Gray }
    } else {
        Write-Host "$yellowWarn No Docker containers running" -ForegroundColor Yellow
    }
} catch {
    Write-Host "$yellowWarn Could not query Docker" -ForegroundColor Yellow
}

Write-Host ""
Write-Host "📊 API TEST" -ForegroundColor Cyan
Write-Host ""

try {
    $threats = Invoke-WebRequest -Uri "http://localhost:3001/api/threats" -TimeoutSec 2 | ConvertFrom-Json
    Write-Host "  $greenCheck Backend API responding" -ForegroundColor Green
    Write-Host "    Data points available: $($threats.Count)" -ForegroundColor Gray
} catch {
    Write-Host "  $yellowWarn Backend API not responding" -ForegroundColor Yellow
}

Write-Host ""
Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host ""

# Summary
$passCount = ($results | Where-Object { $_ -eq $true }).Count
$totalCount = $results.Count

if ($passCount -eq $totalCount) {
    Write-Host "✅ ALL SYSTEMS OPERATIONAL! System is ready to use." -ForegroundColor Green
} elseif ($passCount -gt 0) {
    Write-Host "⚠️  Partial system operational ($passCount/$totalCount services running)" -ForegroundColor Yellow
} else {
    Write-Host "❌ System not responding. Check services are running." -ForegroundColor Red
}

Write-Host ""
Write-Host "🌐 ACCESS POINTS:" -ForegroundColor Cyan
Write-Host "  • Frontend: http://localhost:3000" -ForegroundColor Magenta
Write-Host "  • Backend:  http://localhost:3001" -ForegroundColor Magenta
Write-Host "  • Health:   http://localhost:8081/health" -ForegroundColor Magenta
Write-Host "  • Metrics:  http://localhost:9090/metrics" -ForegroundColor Magenta
Write-Host ""
