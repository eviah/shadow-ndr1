#!/usr/bin/env pwsh
# Shadow NDR - Troubleshooting and Diagnostics
# This script helps diagnose common issues

param(
    [switch]$Full = $false,
    [switch]$KillPorts = $false,
    [switch]$CleanAll = $false
)

$ErrorActionPreference = "Continue"

# Colors
$Green = "Green"
$Yellow = "Yellow"
$Red = "Red"
$Cyan = "Cyan"

Write-Host "`n╔════════════════════════════════════════════════════════════════╗" -ForegroundColor $Cyan
Write-Host "║     Shadow NDR - Troubleshooting & Diagnostics                 ║" -ForegroundColor $Cyan
Write-Host "╚════════════════════════════════════════════════════════════════╝`n" -ForegroundColor $Cyan

# ============================================================================
# Check Prerequisites
# ============================================================================
Write-Host "┌─ CHECKING PREREQUISITES ───────────────────────────────────────┐" -ForegroundColor $Cyan
Write-Host "│                                                                 │" -ForegroundColor $Cyan

# Docker
Write-Host "Docker:" -ForegroundColor $Cyan -NoNewline
try {
    $dockerVersion = & docker --version 2>&1
    Write-Host " ✅ $dockerVersion" -ForegroundColor $Green
} catch {
    Write-Host " ❌ Not installed - Install Docker Desktop" -ForegroundColor $Red
}

# Docker Compose
Write-Host "Docker Compose:" -ForegroundColor $Cyan -NoNewline
try {
    $composeVersion = & docker compose version 2>&1
    Write-Host " ✅ $composeVersion" -ForegroundColor $Green
} catch {
    Write-Host " ❌ Not installed" -ForegroundColor $Red
}

# Python
Write-Host "Python:" -ForegroundColor $Cyan -NoNewline
try {
    $pythonVersion = & python --version 2>&1
    Write-Host " ✅ $pythonVersion" -ForegroundColor $Green
} catch {
    Write-Host " ❌ Not in PATH - Add Python 3.12+ to PATH" -ForegroundColor $Red
}

# Node.js
Write-Host "Node.js:" -ForegroundColor $Cyan -NoNewline
try {
    $nodeVersion = & node --version 2>&1
    Write-Host " ✅ $nodeVersion" -ForegroundColor $Green
} catch {
    Write-Host " ❌ Not installed - Install Node.js 18+" -ForegroundColor $Red
}

# Go
Write-Host "Go:" -ForegroundColor $Cyan -NoNewline
try {
    $goVersion = & go version 2>&1
    Write-Host " ✅ Go $goVersion" -ForegroundColor $Green
} catch {
    Write-Host " ❌ Not installed - Install Go 1.23+" -ForegroundColor $Red
}

Write-Host "│                                                                 │" -ForegroundColor $Cyan
Write-Host "└─────────────────────────────────────────────────────────────────┘`n" -ForegroundColor $Cyan

# ============================================================================
# Check Ports
# ============================================================================
Write-Host "┌─ CHECKING PORTS ───────────────────────────────────────────────┐" -ForegroundColor $Cyan
Write-Host "│                                                                 │" -ForegroundColor $Cyan

$Ports = @(5173, 8000, 8001, 5432, 6379, 8123, 9092, 9000)
$PortsInUse = @()

foreach ($Port in $Ports) {
    $Connection = Get-NetTCPConnection -LocalPort $Port -ErrorAction SilentlyContinue
    if ($Connection) {
        Write-Host "Port $Port: ❌ In use (PID: $($Connection.OwningProcess))" -ForegroundColor $Yellow
        $PortsInUse += @{ Port = $Port; PID = $Connection.OwningProcess }
    } else {
        Write-Host "Port $Port: ✅ Available" -ForegroundColor $Green
    }
}

Write-Host "│                                                                 │" -ForegroundColor $Cyan
Write-Host "└─────────────────────────────────────────────────────────────────┘`n" -ForegroundColor $Cyan

# ============================================================================
# Kill Ports if Requested
# ============================================================================
if ($KillPorts -and $PortsInUse.Count -gt 0) {
    Write-Host "┌─ KILLING PROCESSES ON USED PORTS ─────────────────────────────┐" -ForegroundColor $Yellow
    Write-Host "│                                                                 │" -ForegroundColor $Yellow
    
    foreach ($Item in $PortsInUse) {
        try {
            Stop-Process -Id $Item.PID -Force -ErrorAction Stop
            Write-Host "Killed process $($Item.PID) on port $($Item.Port): ✅" -ForegroundColor $Green
        } catch {
            Write-Host "Failed to kill process $($Item.PID): ❌" -ForegroundColor $Red
        }
    }
    
    Write-Host "│                                                                 │" -ForegroundColor $Yellow
    Write-Host "└─────────────────────────────────────────────────────────────────┘`n" -ForegroundColor $Yellow
}

# ============================================================================
# Check Docker Containers
# ============================================================================
Write-Host "┌─ DOCKER CONTAINERS ────────────────────────────────────────────┐" -ForegroundColor $Cyan
Write-Host "│                                                                 │" -ForegroundColor $Cyan

try {
    $Containers = docker ps -a --format "{{.Names}},{{.Status}}" | ConvertFrom-String -PropertyNames Name, Status
    
    if ($Containers) {
        foreach ($Container in $Containers) {
            if ($Container.Status -like "*Up*") {
                Write-Host "$($Container.Name): ✅ Running" -ForegroundColor $Green
            } else {
                Write-Host "$($Container.Name): ⏹️  Stopped" -ForegroundColor $Yellow
            }
        }
    } else {
        Write-Host "No containers found. Start with: docker-compose up -d" -ForegroundColor $Yellow
    }
} catch {
    Write-Host "Error checking containers: $_" -ForegroundColor $Red
}

Write-Host "│                                                                 │" -ForegroundColor $Cyan
Write-Host "└─────────────────────────────────────────────────────────────────┘`n" -ForegroundColor $Cyan

# ============================================================================
# Check File Structure
# ============================================================================
if ($Full) {
    Write-Host "┌─ FILE STRUCTURE ───────────────────────────────────────────────┐" -ForegroundColor $Cyan
    Write-Host "│                                                                 │" -ForegroundColor $Cyan
    
    $Files = @(
        ".env",
        "shadow-api\requirements.txt",
        "shadow-ml\requirements.txt",
        "shadow-ingestion\main.go",
        "shadow-ui\package.json"
    )
    
    foreach ($File in $Files) {
        $FullPath = Join-Path (Get-Location) $File
        if (Test-Path $FullPath) {
            Write-Host "$File: ✅ Present" -ForegroundColor $Green
        } else {
            Write-Host "$File: ❌ Missing" -ForegroundColor $Red
        }
    }
    
    Write-Host "│                                                                 │" -ForegroundColor $Cyan
    Write-Host "└─────────────────────────────────────────────────────────────────┘`n" -ForegroundColor $Cyan
}

# ============================================================================
# Clean All (WARNING)
# ============================================================================
if ($CleanAll) {
    Write-Host "┌─ CLEAN ALL (WARNING) ──────────────────────────────────────────┐" -ForegroundColor $Red
    Write-Host "│                                                                 │" -ForegroundColor $Red
    
    $Confirm = Read-Host "This will delete all Docker containers and volumes. Continue? (yes/no)"
    
    if ($Confirm -eq "yes") {
        Write-Host "Removing all containers..." -ForegroundColor $Yellow
        docker compose down -v
        Write-Host "✅ Cleanup complete" -ForegroundColor $Green
    } else {
        Write-Host "❌ Cancelled" -ForegroundColor $Yellow
    }
    
    Write-Host "│                                                                 │" -ForegroundColor $Red
    Write-Host "└─────────────────────────────────────────────────────────────────┘`n" -ForegroundColor $Red
}

# ============================================================================
# Recommendations
# ============================================================================
Write-Host "┌─ NEXT STEPS ───────────────────────────────────────────────────┐" -ForegroundColor $Cyan
Write-Host "│                                                                 │" -ForegroundColor $Cyan
Write-Host "│ If everything looks good, run:                                 │" -ForegroundColor $Cyan
Write-Host "│                                                                 │" -ForegroundColor $Cyan
Write-Host "│   .\start-all-services.ps1                                     │" -ForegroundColor $Green
Write-Host "│                                                                 │" -ForegroundColor $Cyan
Write-Host "│ If ports are in use, run:                                      │" -ForegroundColor $Cyan
Write-Host "│                                                                 │" -ForegroundColor $Cyan
Write-Host "│   .\troubleshoot.ps1 -KillPorts                                │" -ForegroundColor $Green
Write-Host "│                                                                 │" -ForegroundColor $Cyan
Write-Host "│ For full diagnostics, run:                                     │" -ForegroundColor $Cyan
Write-Host "│                                                                 │" -ForegroundColor $Cyan
Write-Host "│   .\troubleshoot.ps1 -Full                                     │" -ForegroundColor $Green
Write-Host "│                                                                 │" -ForegroundColor $Cyan
Write-Host "└─────────────────────────────────────────────────────────────────┘`n" -ForegroundColor $Cyan

Write-Host "Done!" -ForegroundColor $Green
