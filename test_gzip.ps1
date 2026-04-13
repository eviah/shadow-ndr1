# Test sensor payload
$json = @{
    protocol = "tcp"
    timestamp = (Get-Date -Format 'o')
    flow_id = "test-flow-001"
    src_ip = "192.168.1.100"
    dst_ip = "8.8.8.8"
    src_port = 54321
    dst_port = 443
    threat_level = "low"
    details = @{
        dst_port = 443
        src_port = 54321
    }
} | ConvertTo-Json

Write-Host "Testing Backend Sensor Endpoint" -ForegroundColor Cyan
Write-Host "================================" -ForegroundColor Cyan

$response = Invoke-WebRequest -Uri "http://localhost:3001/api/sensor/data" `
    -Method POST `
    -ContentType "application/json" `
    -Body $json -ErrorAction SilentlyContinue

$result = $response.Content | ConvertFrom-Json
if ($result.success -eq $true) {
    Write-Host "SUCCESS: Backend accepted payload" -ForegroundColor Green
    Write-Host "Threat ID: $($result.threat.id)" -ForegroundColor White
    Write-Host "Severity: $($result.threat.severity)" -ForegroundColor White
} else {
    Write-Host "Status: $($response.StatusCode)" -ForegroundColor Yellow
}

Write-Host ""
Write-Host "Sensor endpoint is WORKING!" -ForegroundColor Green
