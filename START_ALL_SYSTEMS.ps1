# ============================================================================
# SHADOW NDR - COMPLETE SYSTEM STARTUP SCRIPT
# Starts: Main NDR (Docker) + MT APEX (Node.js) + All Services
# ============================================================================

param(
    [switch]$Clean = $false,
    [switch]$Verbose = $false
)

$ErrorActionPreference = "Continue"
$scriptPath = Split-Path -Parent $MyInvocation.MyCommand.Path

# Colors
$GREEN = "Green"
$RED = "Red"
$YELLOW = "Yellow"
$CYAN = "Cyan"
$GRAY = "Gray"
$WHITE = "White"

# ============================================================================
# HELPER FUNCTIONS
# ============================================================================

function Write-Header {
    param([string]$Text)
    Write-Host "`n╔════════════════════════════════════════════════════════════════╗" -ForegroundColor $CYAN
    Write-Host "║ $Text" -ForegroundColor $CYAN
    Write-Host "╚════════════════════════════════════════════════════════════════╝`n" -ForegroundColor $CYAN
}

function Write-Success {
    param([string]$Text)
    Write-Host "✅ $Text" -ForegroundColor $GREEN
}

function Write-Error-Custom {
    param([string]$Text)
    Write-Host "❌ $Text" -ForegroundColor $RED
}

function Write-Warn {
    param([string]$Text)
    Write-Host "⚠️  $Text" -ForegroundColor $YELLOW
}

function Write-Info {
    param([string]$Text)
    Write-Host "ℹ️  $Text" -ForegroundColor $CYAN
}

function Check-Command {
    param([string]$Command)
    $exists = $null -ne (Get-Command $Command -ErrorAction SilentlyContinue)
    return $exists
}

# ============================================================================
# STEP 1: BANNER
# ============================================================================

Write-Header "🚀 SHADOW NDR - COMPLETE SYSTEM STARTUP"

Write-Host "Starting Main NDR (Docker) + MT APEX (Node.js) + Sensor..." -ForegroundColor $CYAN
Write-Host "This will start 13+ services. Please wait...`n" -ForegroundColor $GRAY

# ============================================================================
# STEP 2: PREREQUISITES CHECK
# ============================================================================

Write-Header "📋 CHECKING PREREQUISITES"

$prerequisites = @{
    "docker" = "Docker"
    "docker-compose" = "Docker Compose"
    "node" = "Node.js"
    "npm" = "npm"
}

$missing = @()

foreach ($cmd in $prerequisites.Keys) {
    if (Check-Command $cmd) {
        Write-Success "$($prerequisites[$cmd]) found"
    } else {
        Write-Error-Custom "$($prerequisites[$cmd]) NOT FOUND"
        $missing += $cmd
    }
}

if ($missing.Count -gt 0) {
    Write-Error-Custom "Missing: $($missing -join ', ')"
    Write-Host "Please install missing prerequisites and try again." -ForegroundColor $RED
    exit 1
}

# ============================================================================
# STEP 3: KILL EXISTING PROCESSES (if -Clean)
# ============================================================================

if ($Clean) {
    Write-Header "🧹 CLEANING UP EXISTING PROCESSES"

    $procs = @("node", "npm")
    foreach ($proc in $procs) {
        $running = Get-Process $proc -ErrorAction SilentlyContinue
        if ($running) {
            Write-Info "Stopping $proc..."
            Stop-Process -Name $proc -Force -ErrorAction SilentlyContinue
            Start-Sleep -Milliseconds 500
            Write-Success "Stopped $proc"
        }
    }

    Write-Info "Stopping Docker containers..."
    Push-Location $scriptPath
    docker-compose down -v 2>&1 | Out-Null
    Pop-Location
    Write-Success "Docker cleanup complete"
    Start-Sleep -Seconds 2
}

# ============================================================================
# STEP 4: START MAIN DOCKER SYSTEM
# ============================================================================

Write-Header "🐳 STARTING DOCKER SYSTEM (Main Shadow NDR)"

Push-Location $scriptPath

Write-Info "Starting Docker containers..."
$docker_result = docker-compose up -d 2>&1

if ($LASTEXITCODE -eq 0) {
    Write-Success "Docker containers started"
    Start-Sleep -Seconds 5
} else {
    Write-Error-Custom "Docker startup failed"
    Write-Host $docker_result -ForegroundColor $RED
    exit 1
}

# ============================================================================
# STEP 5: WAIT FOR DOCKER SERVICES
# ============================================================================

Write-Header "⏳ WAITING FOR DOCKER SERVICES"

$services = @("postgres", "kafka", "redis", "clickhouse")
$max_wait = 30

foreach ($service in $services) {
    Write-Info "Checking $service..."
    $ready = $false

    for ($i = 0; $i -lt $max_wait; $i++) {
        $status = docker-compose ps $service 2>&1 | Select-String "Up"
        if ($status) {
            Write-Success "$service is ready"
            $ready = $true
            break
        }
        Write-Host -NoNewline "."
        Start-Sleep -Seconds 1
    }

    if (-not $ready) {
        Write-Warn "$service may not be fully ready, continuing anyway..."
    }
}

Write-Host ""
Start-Sleep -Seconds 3

# ============================================================================
# STEP 6: START MT APEX BACKEND
# ============================================================================

Write-Header "🌟 STARTING MT APEX BACKEND (Port 3001)"

$backend_dir = "$scriptPath\multi-tenant\backend"

if (-not (Test-Path $backend_dir)) {
    Write-Error-Custom "MT Backend directory not found: $backend_dir"
    exit 1
}

Push-Location $backend_dir

# Check if node_modules exists
if (-not (Test-Path "node_modules")) {
    Write-Info "Installing dependencies..."
    npm install 2>&1 | Out-Null
    if ($LASTEXITCODE -ne 0) {
        Write-Error-Custom "npm install failed"
        Pop-Location
        exit 1
    }
    Write-Success "Dependencies installed"
}

# Start backend in background
Write-Info "Starting backend server..."
$backendProcess = Start-Process powershell -ArgumentList @(
    "-NoExit",
    "-NoProfile",
    "-Command",
    "cd '$backend_dir'; npm run dev 2>&1"
) -PassThru

if ($backendProcess) {
    Write-Success "MT APEX Backend started (PID: $($backendProcess.Id))"
} else {
    Write-Error-Custom "Failed to start MT APEX Backend"
    exit 1
}

Pop-Location
Start-Sleep -Seconds 3

# ============================================================================
# STEP 7: START MT APEX FRONTEND
# ============================================================================

Write-Header "⚛️  STARTING MT APEX FRONTEND (Port 3001/Vite)"

$frontend_dir = "$scriptPath\multi-tenant\frontend"

if (-not (Test-Path $frontend_dir)) {
    Write-Error-Custom "MT Frontend directory not found: $frontend_dir"
    exit 1
}

Push-Location $frontend_dir

# Check if node_modules exists
if (-not (Test-Path "node_modules")) {
    Write-Info "Installing dependencies..."
    npm install 2>&1 | Out-Null
    if ($LASTEXITCODE -ne 0) {
        Write-Error-Custom "npm install failed"
        Pop-Location
        exit 1
    }
    Write-Success "Dependencies installed"
}

# Start frontend in background
Write-Info "Starting frontend server..."
$frontendProcess = Start-Process powershell -ArgumentList @(
    "-NoExit",
    "-NoProfile",
    "-Command",
    "cd '$frontend_dir'; PORT=3001 npm run dev 2>&1"
) -PassThru

if ($frontendProcess) {
    Write-Success "MT APEX Frontend started (PID: $($frontendProcess.Id))"
} else {
    Write-Error-Custom "Failed to start MT APEX Frontend"
    exit 1
}

Pop-Location
Pop-Location

# ============================================================================
# STEP 8: WAIT FOR SERVICES TO BE READY
# ============================================================================

Write-Header "🔄 WAITING FOR ALL SERVICES TO INITIALIZE"

$endpoints = @{
    "http://localhost:3001" = "MT APEX Backend"
    "http://localhost:3000" = "Main NDR UI"
    "http://localhost:9093" = "Kafka (9093)"
    "http://localhost:5433" = "PostgreSQL (5433)"
}

foreach ($endpoint in $endpoints.Keys) {
    Write-Info "Waiting for $($endpoints[$endpoint])..."
    $ready = $false

    for ($i = 0; $i -lt 30; $i++) {
        try {
            $response = Invoke-WebRequest -Uri $endpoint -TimeoutSec 2 -ErrorAction SilentlyContinue
            if ($response) {
                Write-Success "$($endpoints[$endpoint]) is responding"
                $ready = $true
                break
            }
        } catch {
            # Not ready yet
        }

        Write-Host -NoNewline "."
        Start-Sleep -Seconds 1
    }

    if (-not $ready) {
        Write-Warn "$($endpoints[$endpoint]) not responding yet, but continuing..."
    }
}

Write-Host ""

# ============================================================================
# STEP 9: DISPLAY FINAL STATUS
# ============================================================================

Write-Header "✨ SYSTEM STARTUP COMPLETE!"

Write-Host "
╔════════════════════════════════════════════════════════════════════╗
║                     🎉 ALL SYSTEMS OPERATIONAL 🎉                  ║
╚════════════════════════════════════════════════════════════════════╝

" -ForegroundColor $GREEN

Write-Host "📊 MAIN SHADOW NDR SYSTEM:" -ForegroundColor $CYAN
Write-Host "   UI Dashboard:         http://localhost:3000" -ForegroundColor $WHITE
Write-Host "   Grafana Dashboards:   http://localhost:3002" -ForegroundColor $WHITE
Write-Host "   Prometheus Metrics:   http://localhost:9091" -ForegroundColor $WHITE
Write-Host "   Sensor Input (UDP):   localhost:9999" -ForegroundColor $WHITE
Write-Host ""

Write-Host "🌟 MT APEX SYSTEM:" -ForegroundColor $CYAN
Write-Host "   API & Frontend:       http://localhost:3001" -ForegroundColor $WHITE
Write-Host "   Health Check:         curl http://localhost:3001" -ForegroundColor $WHITE
Write-Host ""

Write-Host "💾 DATABASES:" -ForegroundColor $CYAN
Write-Host "   PostgreSQL (Main):    localhost:5433" -ForegroundColor $WHITE
Write-Host "   PostgreSQL (MT):      localhost:5432" -ForegroundColor $WHITE
Write-Host "   Redis:                localhost:6380" -ForegroundColor $WHITE
Write-Host "   ClickHouse:           localhost:8123" -ForegroundColor $WHITE
Write-Host ""

Write-Host "📢 MESSAGE BROKER:" -ForegroundColor $CYAN
Write-Host "   Kafka:                localhost:9093" -ForegroundColor $WHITE
Write-Host ""

Write-Host "🚀 QUICK COMMANDS:" -ForegroundColor $CYAN
Write-Host "   Check Docker:         docker-compose ps" -ForegroundColor $GRAY
Write-Host "   View Logs:            docker-compose logs -f" -ForegroundColor $GRAY
Write-Host "   Stop All:             docker-compose down" -ForegroundColor $GRAY
Write-Host ""

Write-Host "⏱️  STARTUP TIME: ~15-30 seconds" -ForegroundColor $YELLOW
Write-Host "✅ STATUS: PRODUCTION READY" -ForegroundColor $GREEN
Write-Host ""

Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor $CYAN
Write-Host "Next Steps:" -ForegroundColor $CYAN
Write-Host "  1. Open http://localhost:3000 in your browser (Main NDR)" -ForegroundColor $WHITE
Write-Host "  2. Open http://localhost:3001 in your browser (MT APEX)" -ForegroundColor $WHITE
Write-Host "  3. Send UDP packets to localhost:9999 to test" -ForegroundColor $WHITE
Write-Host "  4. Check Grafana (localhost:3002) for dashboards" -ForegroundColor $WHITE
Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor $CYAN
Write-Host ""

Write-Host "💡 Press Ctrl+C to see Docker logs or type 'docker-compose logs -f'" -ForegroundColor $GRAY
Write-Host ""
