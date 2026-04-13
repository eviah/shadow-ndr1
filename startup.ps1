# Wait for Docker to be ready, then start all services
Write-Host "🐳 Waiting for Docker Desktop to initialize..." -ForegroundColor Cyan
$maxWait = 60  # 60 seconds max wait
$elapsed = 0

while ($elapsed -lt $maxWait) {
    $dockerReady = docker ps 2>&1 | Out-String
    if ($dockerReady -and -not $dockerReady.Contains("Error")) {
        Write-Host "✅ Docker is ready!" -ForegroundColor Green
        break
    }
    Write-Host "   Waiting... ($elapsed/$maxWait sec)" -ForegroundColor Yellow
    Start-Sleep -Seconds 2
    $elapsed += 2
}

if ($elapsed -ge $maxWait) {
    Write-Host "❌ Docker failed to start after $maxWait seconds" -ForegroundColor Red
    Write-Host "Please check Docker Desktop is running and try again" -ForegroundColor Yellow
    exit 1
}

# Now start all services
Write-Host "`n🚀 Starting Shadow NDR system..." -ForegroundColor Cyan
& ".\start-all-services.ps1"
