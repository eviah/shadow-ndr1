@echo off
REM Shadow NDR - Multi-Service Startup Script (Batch)
REM This script opens separate terminals for each service using PowerShell

setlocal enabledelayedexpansion

echo.
echo ╔════════════════════════════════════════════════════════════════╗
echo ║     Shadow NDR - Launching All Services                        ║
echo ║     This will open 6 new terminals                             ║
echo ╚════════════════════════════════════════════════════════════════╝
echo.

REM Get the current directory
set BASE_DIR=%cd%

REM Define Python and Go paths
set PYTHON_PATH=C:\Users\liorh\AppData\Local\Programs\Python\Python312
set GO_PATH=C:\Program Files\Go\bin

REM Terminal 1: Databases (Docker)
echo [1/6] Starting databases (PostgreSQL, Redis, ClickHouse, Kafka)...
start "Shadow-Databases" pwsh -NoExit -Command "cd '%BASE_DIR%\deploy'; Write-Host 'Starting Docker containers...' -ForegroundColor Cyan; docker compose up -d; Write-Host 'Databases started. Waiting 30 seconds for initialization...' -ForegroundColor Green; Start-Sleep -Seconds 30; Write-Host 'Databases ready!' -ForegroundColor Green"

REM Wait for databases to start
timeout /t 35 /nobreak

REM Terminal 2: Backend API
echo [2/6] Starting Backend API (shadow-api)...
start "Shadow-API" pwsh -NoExit -Command "$env:PATH = '%PYTHON_PATH%\Scripts;%PYTHON_PATH%;$env:PATH'; cd '%BASE_DIR%\shadow-api'; Write-Host 'Activating Python environment...' -ForegroundColor Cyan; if (-not (Test-Path 'venv')) { python -m venv venv }; .\venv\Scripts\Activate.ps1; Write-Host 'Installing dependencies...' -ForegroundColor Cyan; pip install -r requirements.txt -q; Write-Host 'Running database migrations...' -ForegroundColor Cyan; python run_migrations.py; Write-Host 'Starting API server on http://localhost:8000' -ForegroundColor Green; uvicorn app.main:app --reload --host 0.0.0.0 --port 8000"

REM Terminal 3: ML Service
echo [3/6] Starting ML Service (shadow-ml)...
start "Shadow-ML" pwsh -NoExit -Command "$env:PATH = '%PYTHON_PATH%\Scripts;%PYTHON_PATH%;$env:PATH'; cd '%BASE_DIR%\shadow-ml'; Write-Host 'Activating Python environment...' -ForegroundColor Cyan; if (-not (Test-Path 'venv')) { python -m venv venv }; .\venv\Scripts\Activate.ps1; Write-Host 'Installing dependencies...' -ForegroundColor Cyan; pip install -r requirements.txt -q; Write-Host 'Starting ML service on http://localhost:8001' -ForegroundColor Green; uvicorn app.main:app --reload --host 0.0.0.0 --port 8001"

REM Terminal 4: Data Ingestion
echo [4/6] Starting Data Ingestion (shadow-ingestion)...
start "Shadow-Ingestion" pwsh -NoExit -Command "$env:PATH = '%GO_PATH%;$env:PATH'; cd '%BASE_DIR%\shadow-ingestion'; if (Test-Path 'shadow-ingestion.exe') { Write-Host 'Using pre-built executable...' -ForegroundColor Green; .\shadow-ingestion.exe } else { Write-Host 'Building shadow-ingestion...' -ForegroundColor Cyan; go build -o shadow-ingestion.exe main.go; .\shadow-ingestion.exe }"

REM Terminal 5: Network Sensor
echo [5/6] Starting Network Sensor (shadow-sensor)...
start "Shadow-Sensor" pwsh -NoExit -Command "$env:PATH = '%GO_PATH%;$env:PATH'; cd '%BASE_DIR%\shadow-sensor'; Write-Host 'Starting network sensor...' -ForegroundColor Green; go run src/main.rs"

REM Terminal 6: Frontend UI
echo [6/6] Starting Frontend (shadow-ui)...
start "Shadow-UI" pwsh -NoExit -Command "cd '%BASE_DIR%\shadow-ui'; Write-Host 'Installing frontend dependencies...' -ForegroundColor Cyan; if (-not (Test-Path 'node_modules')) { npm install }; Write-Host 'Starting Vite dev server on http://localhost:5173' -ForegroundColor Green; npm run dev"

echo.
echo ╔════════════════════════════════════════════════════════════════╗
echo ║     ✅ All services are starting in separate terminals         ║
echo ║                                                                ║
echo ║     Services will be available at:                            ║
echo ║     - Frontend:    http://localhost:5173                      ║
echo ║     - Backend API: http://localhost:8000                      ║
echo ║     - ML Service:  http://localhost:8001                      ║
echo ║     - API Docs:    http://localhost:8000/docs                 ║
echo ║                                                                ║
echo ║     Wait 60 seconds for all services to fully initialize.     ║
echo ║                                                                ║
echo ║     Then verify with: .\verify-integration.ps1 -Full          ║
echo ╚════════════════════════════════════════════════════════════════╝
echo.

REM Optional: Open verification after delay
timeout /t 60 /nobreak
echo.
echo Launching verification script...
pwsh -NoExit -Command "cd '%BASE_DIR%'; .\verify-integration.ps1 -Full"

endlocal
