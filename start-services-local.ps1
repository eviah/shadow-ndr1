# ============================================================================
# START ALL SERVICES LOCALLY (NO DOCKER REQUIRED)
# ============================================================================

Write-Host "`n🚀 Shadow NDR - Local Development Mode (NO DOCKER)" -ForegroundColor Cyan
Write-Host "========================================================`n" -ForegroundColor Cyan

# Kill any existing processes on ports
Write-Host "🧹 Cleaning up old processes..." -ForegroundColor Yellow
Get-NetTCPConnection -LocalPort 5173 -ErrorAction SilentlyContinue | ForEach-Object { Stop-Process -Id $_.OwningProcess -Force -ErrorAction SilentlyContinue }
Get-NetTCPConnection -LocalPort 8000 -ErrorAction SilentlyContinue | ForEach-Object { Stop-Process -Id $_.OwningProcess -Force -ErrorAction SilentlyContinue }
Get-NetTCPConnection -LocalPort 8001 -ErrorAction SilentlyContinue | ForEach-Object { Stop-Process -Id $_.OwningProcess -Force -ErrorAction SilentlyContinue }
Get-NetTCPConnection -LocalPort 8080 -ErrorAction SilentlyContinue | ForEach-Object { Stop-Process -Id $_.OwningProcess -Force -ErrorAction SilentlyContinue }

Start-Sleep -Seconds 1

# Service definitions
$services = @(
    @{
        name = "Frontend (React)"
        path = "shadow-ui"
        init = "npm install --silent"
        cmd = "npm run dev"
        port = 5173
        check = "Frontend will start on http://localhost:5173"
    },
    @{
        name = "Backend API (FastAPI)"
        path = "shadow-api"
        init = "python -m pip install -q -r requirements.txt"
        cmd = "python -m uvicorn app.main:app --reload --port 8000"
        port = 8000
        check = "API docs at http://localhost:8000/docs"
    },
    @{
        name = "ML Service (Python)"
        path = "shadow-ml"
        init = "python -m pip install -q -r requirements.txt"
        cmd = "python -m uvicorn app.main:app --reload --port 8001"
        port = 8001
        check = "ML API at http://localhost:8001/docs"
    },
    @{
        name = "Data Ingestion (Go)"
        path = "shadow-ingestion"
        init = "go mod download"
        cmd = "go run main.go"
        port = 8080
        check = "Ingestion running on port 8080"
    }
)

# Start each service in a new terminal
$pidList = @()

foreach ($service in $services) {
    Write-Host "📍 Starting: $($service.name) (Port $($service.port))" -ForegroundColor Green
    Write-Host "   $($service.check)" -ForegroundColor Gray
    
    # Create initialization and execution script
    $script = @"
`$ErrorActionPreference = 'Continue'
cd 'c:\Users\liorh\shadow-ndr\$($service.path)'

# Initialize dependencies
Write-Host '📦 Initializing dependencies...' -ForegroundColor Yellow
$($service.init)

# Run service
Write-Host '✅ Starting $($service.name)...' -ForegroundColor Green
Write-Host '📍 Press Ctrl+C to stop this service' -ForegroundColor Gray
$($service.cmd)
"@
    
    # Start in new terminal window
    $process = Start-Process powershell -ArgumentList "-NoExit", "-Command", $script -PassThru
    $pidList += $process.Id
    
    Write-Host "   PID: $($process.Id)" -ForegroundColor Gray
    Start-Sleep -Seconds 2
}

# Summary
Write-Host "`n========================================================" -ForegroundColor Cyan
Write-Host "✅ ALL SERVICES STARTED!`n" -ForegroundColor Green

Write-Host "📱 Frontend (React):     http://localhost:5173" -ForegroundColor Cyan
Write-Host "🔌 API Docs (Swagger):   http://localhost:8000/docs" -ForegroundColor Cyan
Write-Host "🤖 ML Service (Swagger): http://localhost:8001/docs" -ForegroundColor Cyan
Write-Host "📊 Data Pipeline:        Ingestion service running`n" -ForegroundColor Cyan

Write-Host "⏰ Waiting 15 seconds for services to fully initialize..." -ForegroundColor Yellow
Start-Sleep -Seconds 15

# Try to open frontend
Write-Host "`n🌐 Opening frontend in browser..." -ForegroundColor Green
Start-Process "http://localhost:5173"

Write-Host "`n✨ Development environment ready!" -ForegroundColor Green
Write-Host "💡 All services running in separate terminals above" -ForegroundColor Gray
Write-Host "🛑 Close any terminal to stop that service`n" -ForegroundColor Gray

# Keep this window alive
Write-Host "Press Ctrl+C to stop monitoring" -ForegroundColor Yellow
while ($true) { Start-Sleep -Seconds 60 }
