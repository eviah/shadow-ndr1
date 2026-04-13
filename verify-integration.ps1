#!/usr/bin/env pwsh
# Shadow NDR - Service Connection Verification Script
# Validates all service connections and integration health

param(
    [switch]$Verbose = $false,
    [switch]$Full = $false
)

$ErrorActionPreference = "Continue"

# Colors for output
$Success = "Green"
$Warning = "Yellow"
$Error = "Red"
$Info = "Cyan"

Write-Host "`n╔════════════════════════════════════════════════════════════════╗" -ForegroundColor $Info
Write-Host "║     Shadow NDR - Service Integration Verification Report       ║" -ForegroundColor $Info
Write-Host "║                    $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')                       ║" -ForegroundColor $Info
Write-Host "╚════════════════════════════════════════════════════════════════╝`n" -ForegroundColor $Info

# Service Configuration
$Services = @(
    @{Name = "Frontend (shadow-ui)"; URL = "http://localhost:5173"; Port = 5173; Type = "Web" }
    @{Name = "Backend API (shadow-api)"; URL = "http://localhost:8000"; Port = 8000; Type = "API" }
    @{Name = "ML Service (shadow-ml)"; URL = "http://localhost:8001"; Port = 8001; Type = "API" }
    @{Name = "PostgreSQL"; URL = "localhost"; Port = 5432; Type = "Database" }
    @{Name = "Redis"; URL = "localhost"; Port = 6379; Type = "Cache" }
    @{Name = "ClickHouse"; URL = "http://localhost:8123"; Port = 8123; Type = "Database" }
    @{Name = "Kafka"; URL = "localhost"; Port = 9092; Type = "Queue" }
)

# API Endpoints to test
$APIEndpoints = @(
    @{Service = "shadow-api"; Endpoint = "/api/v1/auth/me"; Method = "GET"; RequiresAuth = $true }
    @{Service = "shadow-api"; Endpoint = "/api/v1/threats"; Method = "GET"; RequiresAuth = $true }
    @{Service = "shadow-api"; Endpoint = "/api/v1/assets"; Method = "GET"; RequiresAuth = $true }
    @{Service = "shadow-ml"; Endpoint = "/health"; Method = "GET"; RequiresAuth = $false }
)

# Function to test port connectivity
function Test-PortConnection {
    param(
        [string]$Hostname,
        [int]$Port,
        [int]$TimeoutMS = 1000
    )
    
    $tcpClient = New-Object System.Net.Sockets.TcpClient
    $asyncResult = $tcpClient.BeginConnect($Hostname, $Port, $null, $null)
    $asyncResult.AsyncWaitHandle.WaitOne($TimeoutMS) | Out-Null
    
    try {
        if ($tcpClient.Connected) {
            $tcpClient.Close()
            return $true
        }
    }
    catch {
        return $false
    }
    
    return $false
}

# Function to test HTTP endpoint
function Test-HTTPEndpoint {
    param(
        [string]$URL,
        [int]$TimeoutSec = 5
    )
    
    try {
        $response = Invoke-WebRequest -Uri $URL -TimeoutSec $TimeoutSec -ErrorAction Stop -SkipHttpErrorCheck
        return @{
            Success = $true
            StatusCode = $response.StatusCode
            Message = "OK"
        }
    }
    catch {
        return @{
            Success = $false
            StatusCode = 0
            Message = $_.Exception.Message
        }
    }
}

# ============================================================================
# 1. TEST SERVICE CONNECTIVITY
# ============================================================================
Write-Host "┌─ SERVICE CONNECTIVITY CHECKS ─────────────────────────────────┐" -ForegroundColor $Info
Write-Host "│                                                                 │" -ForegroundColor $Info

$connectionResults = @()

foreach ($service in $Services) {
    Write-Host "Testing: $($service.Name)..." -ForegroundColor $Info -NoNewline
    
    if ($service.Type -eq "Web") {
        $result = Test-HTTPEndpoint -URL $service.URL -TimeoutSec 3
        if ($result.Success) {
            Write-Host " ✅ Connected" -ForegroundColor $Success
            $connectionResults += @{Service = $service.Name; Status = "OK"; Port = $service.Port }
        }
        else {
            Write-Host " ❌ Failed - $($result.Message)" -ForegroundColor $Error
            $connectionResults += @{Service = $service.Name; Status = "FAILED"; Port = $service.Port }
        }
    }
    else {
        $connected = Test-PortConnection -Hostname $service.URL -Port $service.Port
        if ($connected) {
            Write-Host " ✅ Connected (Port $($service.Port))" -ForegroundColor $Success
            $connectionResults += @{Service = $service.Name; Status = "OK"; Port = $service.Port }
        }
        else {
            Write-Host " ❌ Connection Refused (Port $($service.Port))" -ForegroundColor $Error
            $connectionResults += @{Service = $service.Name; Status = "FAILED"; Port = $service.Port }
        }
    }
}

Write-Host "│                                                                 │" -ForegroundColor $Info
Write-Host "└─────────────────────────────────────────────────────────────────┘`n" -ForegroundColor $Info

# ============================================================================
# 2. TEST API ENDPOINTS
# ============================================================================
Write-Host "┌─ API ENDPOINT VERIFICATION ────────────────────────────────────┐" -ForegroundColor $Info
Write-Host "│                                                                 │" -ForegroundColor $Info

$apiResults = @()

foreach ($endpoint in $APIEndpoints) {
    $baseURL = if ($endpoint.Service -eq "shadow-api") { "http://localhost:8000" } else { "http://localhost:8001" }
    $fullURL = "$baseURL$($endpoint.Endpoint)"
    
    Write-Host "Testing: $($endpoint.Service) - $($endpoint.Endpoint)..." -ForegroundColor $Info -NoNewline
    
    $result = Test-HTTPEndpoint -URL $fullURL
    
    if ($result.Success -or $result.StatusCode -eq 401) {
        # 401 is OK for protected endpoints (means endpoint exists)
        Write-Host " ✅ Responds" -ForegroundColor $Success
        $apiResults += @{Endpoint = $endpoint.Endpoint; Status = "OK"; Code = $result.StatusCode }
    }
    else {
        Write-Host " ❌ No Response" -ForegroundColor $Error
        $apiResults += @{Endpoint = $endpoint.Endpoint; Status = "FAILED"; Code = $result.StatusCode }
    }
}

Write-Host "│                                                                 │" -ForegroundColor $Info
Write-Host "└─────────────────────────────────────────────────────────────────┘`n" -ForegroundColor $Info

# ============================================================================
# 3. VERIFY FILE STRUCTURE
# ============================================================================
Write-Host "┌─ FILE STRUCTURE VERIFICATION ──────────────────────────────────┐" -ForegroundColor $Info
Write-Host "│                                                                 │" -ForegroundColor $Info

$requiredFiles = @(
    "shadow-ui/.env"
    "shadow-ui/src/config/index.ts"
    "shadow-ui/src/services/api/client.ts"
    "shadow-ui/src/services/api/auth.ts"
    "shadow-ui/src/services/api/threats.ts"
    "shadow-ui/src/services/api/assets.ts"
    "shadow-ui/src/services/websocket/client.ts"
    "shadow-api/migrations/001_create_users_tables.sql"
    "shadow-api/run_migrations.py"
)

$baseDir = "c:\Users\liorh\shadow-ndr"
$fileResults = @()

foreach ($file in $requiredFiles) {
    $fullPath = Join-Path $baseDir $file
    Write-Host "Checking: $file..." -ForegroundColor $Info -NoNewline
    
    if (Test-Path $fullPath) {
        Write-Host " ✅ Present" -ForegroundColor $Success
        $fileResults += @{File = $file; Status = "OK" }
    }
    else {
        Write-Host " ❌ Missing" -ForegroundColor $Error
        $fileResults += @{File = $file; Status = "MISSING" }
    }
}

Write-Host "│                                                                 │" -ForegroundColor $Info
Write-Host "└─────────────────────────────────────────────────────────────────┘`n" -ForegroundColor $Info

# ============================================================================
# 4. CHECK CONFIGURATION FILES
# ============================================================================
Write-Host "┌─ CONFIGURATION VALIDATION ─────────────────────────────────────┐" -ForegroundColor $Info
Write-Host "│                                                                 │" -ForegroundColor $Info

# Check shadow-ui .env
Write-Host "shadow-ui/.env configuration:" -ForegroundColor $Info
$uiEnvPath = Join-Path $baseDir "shadow-ui\.env"
if (Test-Path $uiEnvPath) {
    $uiEnvContent = Get-Content $uiEnvPath
    if ($uiEnvContent -match "VITE_API_URL") {
        Write-Host "  ✅ VITE_API_URL configured" -ForegroundColor $Success
    }
    if ($uiEnvContent -match "VITE_WS_URL") {
        Write-Host "  ✅ VITE_WS_URL configured" -ForegroundColor $Success
    }
}
else {
    Write-Host "  ❌ .env file not found" -ForegroundColor $Error
}

Write-Host "`nshadow-api/.env configuration:" -ForegroundColor $Info
$apiEnvPath = Join-Path $baseDir "shadow-api\.env"
if (Test-Path $apiEnvPath) {
    $apiEnvContent = Get-Content $apiEnvPath
    if ($apiEnvContent -match "DATABASE") {
        Write-Host "  ✅ Database configuration found" -ForegroundColor $Success
    }
}
else {
    Write-Host "  ❌ .env file not found (using defaults)" -ForegroundColor $Warning
}

Write-Host "`n│                                                                 │" -ForegroundColor $Info
Write-Host "└─────────────────────────────────────────────────────────────────┘`n" -ForegroundColor $Info

# ============================================================================
# 5. SUMMARY REPORT
# ============================================================================
Write-Host "┌─ INTEGRATION SUMMARY ──────────────────────────────────────────┐" -ForegroundColor $Info
Write-Host "│                                                                 │" -ForegroundColor $Info

$successCount = ($connectionResults | Where-Object { $_.Status -eq "OK" }).Count
$totalServices = $connectionResults.Count

Write-Host "Services Connected: $successCount / $totalServices" -ForegroundColor $(if ($successCount -eq $totalServices) { $Success } else { $Warning })
Write-Host "API Endpoints: $(($apiResults | Where-Object { $_.Status -eq "OK" }).Count) / $($apiResults.Count) responding" -ForegroundColor $(if (($apiResults | Where-Object { $_.Status -eq "OK" }).Count -eq $apiResults.Count) { $Success } else { $Warning })
Write-Host "Files Present: $(($fileResults | Where-Object { $_.Status -eq "OK" }).Count) / $($fileResults.Count) verified" -ForegroundColor $(if (($fileResults | Where-Object { $_.Status -eq "OK" }).Count -eq $fileResults.Count) { $Success } else { $Warning })

Write-Host "`n│ CONNECTION STATUS:                                               │" -ForegroundColor $Info

if ($successCount -eq $totalServices) {
    Write-Host "│ ✅ ALL SERVICES CONNECTED - SYSTEM READY FOR USE              │" -ForegroundColor $Success
}
elseif ($successCount -gt ($totalServices / 2)) {
    Write-Host "│ ⚠️  PARTIAL CONNECTION - CHECK FAILED SERVICES                │" -ForegroundColor $Warning
}
else {
    Write-Host "│ ❌ CRITICAL ERRORS - MULTIPLE SERVICES OFFLINE                │" -ForegroundColor $Error
}

Write-Host "│                                                                 │" -ForegroundColor $Info
Write-Host "└─────────────────────────────────────────────────────────────────┘`n" -ForegroundColor $Info

# ============================================================================
# 6. DETAILED SERVICE REPORT (if requested)
# ============================================================================
if ($Full) {
    Write-Host "┌─ DETAILED SERVICE REPORT ──────────────────────────────────────┐" -ForegroundColor $Info
    Write-Host "│                                                                 │" -ForegroundColor $Info
    
    foreach ($result in $connectionResults) {
        $statusSymbol = if ($result.Status -eq "OK") { "✅" } else { "❌" }
        Write-Host "│ $statusSymbol $($result.Service.PadRight(50)) │" -ForegroundColor $(if ($result.Status -eq "OK") { $Success } else { $Error })
    }
    
    Write-Host "│                                                                 │" -ForegroundColor $Info
    Write-Host "└─────────────────────────────────────────────────────────────────┘`n" -ForegroundColor $Info
}

# ============================================================================
# 7. TROUBLESHOOTING RECOMMENDATIONS
# ============================================================================
$failedServices = $connectionResults | Where-Object { $_.Status -eq "FAILED" }

if ($failedServices.Count -gt 0) {
    Write-Host "┌─ TROUBLESHOOTING RECOMMENDATIONS ──────────────────────────────┐" -ForegroundColor $Warning
    Write-Host "│                                                                 │" -ForegroundColor $Warning
    
    foreach ($failed in $failedServices) {
        Write-Host "│ Issue: $($failed.Service) (Port $($failed.Port))               │" -ForegroundColor $Warning
        Write-Host "│ Action: Verify service is running on the specified port.     │" -ForegroundColor $Warning
    }
    
    Write-Host "│                                                                 │" -ForegroundColor $Warning
    Write-Host "└─────────────────────────────────────────────────────────────────┘`n" -ForegroundColor $Warning
}

# ============================================================================
# 8. NEXT STEPS
# ============================================================================
Write-Host "┌─ RECOMMENDED NEXT STEPS ───────────────────────────────────────┐" -ForegroundColor $Info
Write-Host "│                                                                 │" -ForegroundColor $Info
Write-Host "│ 1. Open http://localhost:5173 in your browser                 │" -ForegroundColor $Info
Write-Host "│ 2. Log in with admin credentials                              │" -ForegroundColor $Info
Write-Host "│ 3. Verify dashboard displays real-time threat data            │" -ForegroundColor $Info
Write-Host "│ 4. Check WebSocket connection in browser DevTools (F12)       │" -ForegroundColor $Info
Write-Host "│ 5. Monitor logs for any errors                                │" -ForegroundColor $Info
Write-Host "│                                                                 │" -ForegroundColor $Info
Write-Host "└─────────────────────────────────────────────────────────────────┘`n" -ForegroundColor $Info

# ============================================================================
# Final Status
# ============================================================================
if ($successCount -eq $totalServices) {
    Write-Host "🎉 Shadow NDR System: FULLY OPERATIONAL`n" -ForegroundColor $Success
    exit 0
}
else {
    Write-Host "⚠️  Shadow NDR System: NEEDS ATTENTION`n" -ForegroundColor $Warning
    exit 1
}
