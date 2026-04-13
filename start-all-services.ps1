# Shadow NDR - Multi-Service Startup Script (PowerShell)
# This script opens separate terminals for each service
# Usage: .\start-all-services.ps1

param(
    [switch]$SkipVerification = $false,
    [int]$StartupWaitSeconds = 60
)

$ErrorActionPreference = "Continue"

# Define paths
$BaseDir = Get-Location
$PythonPath = "C:\Users\liorh\AppData\Local\Programs\Python\Python312"
$GoPath = "C:\Program Files\Go\bin"

Write-Host "`n╔════════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║     Shadow NDR - Launching All Services                        ║" -ForegroundColor Cyan
Write-Host "║     This will open 6 new terminals                             ║" -ForegroundColor Cyan
Write-Host "╚════════════════════════════════════════════════════════════════╝`n" -ForegroundColor Cyan

# Define service commands
$Services = @(
    @{
        Name = "Databases"
        Title = "Shadow-Databases"
        Command = "cd '$($BaseDir)\deploy'; Write-Host 'Starting Docker containers...' -ForegroundColor Cyan; docker compose up -d; Write-Host 'Databases started. Waiting 30 seconds for initialization...' -ForegroundColor Green; Start-Sleep -Seconds 30; Write-Host 'Databases ready!' -ForegroundColor Green"
        WaitBefore = 0
        WaitAfter = 35
    },
    @{
        Name = "Backend API"
        Title = "Shadow-API"
        Command = "`$env:PATH = '$PythonPath\Scripts;$PythonPath;`$env:PATH'; cd '$($BaseDir)\shadow-api'; Write-Host 'Activating Python environment...' -ForegroundColor Cyan; if (-not (Test-Path 'venv')) { python -m venv venv }; .\venv\Scripts\Activate.ps1; Write-Host 'Installing dependencies...' -ForegroundColor Cyan; pip install -r requirements.txt -q; Write-Host 'Running database migrations...' -ForegroundColor Cyan; python run_migrations.py; Write-Host 'Starting API server on http://localhost:8000' -ForegroundColor Green; uvicorn app.main:app --reload --host 0.0.0.0 --port 8000"
        WaitBefore = 0
        WaitAfter = 0
    },
    @{
        Name = "ML Service"
        Title = "Shadow-ML"
        Command = "`$env:PATH = '$PythonPath\Scripts;$PythonPath;`$env:PATH'; cd '$($BaseDir)\shadow-ml'; Write-Host 'Activating Python environment...' -ForegroundColor Cyan; if (-not (Test-Path 'venv')) { python -m venv venv }; .\venv\Scripts\Activate.ps1; Write-Host 'Installing dependencies...' -ForegroundColor Cyan; pip install -r requirements.txt -q; Write-Host 'Starting ML service on http://localhost:8001' -ForegroundColor Green; uvicorn app.main:app --reload --host 0.0.0.0 --port 8001"
        WaitBefore = 0
        WaitAfter = 0
    },
    @{
        Name = "Data Ingestion"
        Title = "Shadow-Ingestion"
        Command = "`$env:PATH = '$GoPath;`$env:PATH'; cd '$($BaseDir)\shadow-ingestion'; if (Test-Path 'shadow-ingestion.exe') { Write-Host 'Using pre-built executable...' -ForegroundColor Green; .\shadow-ingestion.exe } else { Write-Host 'Building shadow-ingestion...' -ForegroundColor Cyan; go build -o shadow-ingestion.exe main.go; .\shadow-ingestion.exe }"
        WaitBefore = 0
        WaitAfter = 0
    },
    @{
        Name = "Network Sensor"
        Title = "Shadow-Sensor"
        Command = "`$env:PATH = '$GoPath;`$env:PATH'; cd '$($BaseDir)\shadow-sensor'; Write-Host 'Starting network sensor...' -ForegroundColor Green; go run src/main.rs"
        WaitBefore = 0
        WaitAfter = 0
    },
    @{
        Name = "Frontend UI"
        Title = "Shadow-UI"
        Command = "cd '$($BaseDir)\shadow-ui'; Write-Host 'Installing frontend dependencies...' -ForegroundColor Cyan; if (-not (Test-Path 'node_modules')) { npm install }; Write-Host 'Starting Vite dev server on http://localhost:5173' -ForegroundColor Green; npm run dev"
        WaitBefore = 0
        WaitAfter = 0
    }
)

# Launch services
$ServiceIndex = 1
foreach ($Service in $Services) {
    Write-Host "[$ServiceIndex/$($Services.Count)] Starting $($Service.Name)..." -ForegroundColor Yellow
    
    # Wait before launching if specified
    if ($Service.WaitBefore -gt 0) {
        Write-Host "  Waiting $($Service.WaitBefore) seconds..." -ForegroundColor Gray
        Start-Sleep -Seconds $Service.WaitBefore
    }
    
    # Launch service in new terminal
    Start-Process -FilePath "pwsh" -ArgumentList "-NoExit", "-Command", $Service.Command -WindowStyle Normal
    
    # Wait after launching if specified
    if ($Service.WaitAfter -gt 0) {
        Write-Host "  Waiting $($Service.WaitAfter) seconds..." -ForegroundColor Gray
        Start-Sleep -Seconds $Service.WaitAfter
    }
    
    $ServiceIndex++
}

Write-Host "`n╔════════════════════════════════════════════════════════════════╗" -ForegroundColor Green
Write-Host "║     ✅ All services are starting in separate terminals         ║" -ForegroundColor Green
Write-Host "║                                                                ║" -ForegroundColor Green
Write-Host "║     Services will be available at:                            ║" -ForegroundColor Green
Write-Host "║     - Frontend:    http://localhost:5173                      ║" -ForegroundColor Green
Write-Host "║     - Backend API: http://localhost:8000                      ║" -ForegroundColor Green
Write-Host "║     - ML Service:  http://localhost:8001                      ║" -ForegroundColor Green
Write-Host "║     - API Docs:    http://localhost:8000/docs                 ║" -ForegroundColor Green
Write-Host "║                                                                ║" -ForegroundColor Green
Write-Host "║     Wait $StartupWaitSeconds seconds for all services to fully initialize.     ║" -ForegroundColor Green
Write-Host "║                                                                ║" -ForegroundColor Green
Write-Host "╚════════════════════════════════════════════════════════════════╝`n" -ForegroundColor Green

# Wait for services to initialize
Write-Host "Waiting for services to initialize..." -ForegroundColor Cyan
for ($i = $StartupWaitSeconds; $i -gt 0; $i--) {
    Write-Host -NoNewline "`rTime remaining: $i seconds   "
    Start-Sleep -Seconds 1
}
Write-Host "`n" -ForegroundColor Green

# Run verification if not skipped
if (-not $SkipVerification) {
    Write-Host "Launching verification script..." -ForegroundColor Cyan
    & ".\verify-integration.ps1" -Full
} else {
    Write-Host "Skipping verification (use -SkipVerification flag)" -ForegroundColor Yellow
}

Write-Host "`nDone! All services should now be running." -ForegroundColor Green
Write-Host "- Open http://localhost:5173 in your browser" -ForegroundColor Green
Write-Host "- Check API documentation at http://localhost:8000/docs" -ForegroundColor Green
