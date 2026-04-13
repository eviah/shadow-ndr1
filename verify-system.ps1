#!/usr/bin/env powershell
# Verify Shadow NDR System Status

Write-Host ""
Write-Host "SHADOW NDR SYSTEM VERIFICATION" -ForegroundColor Cyan
Write-Host "===============================" -ForegroundColor Cyan
Write-Host ""

$passed = 0
$failed = 0

# Test 1: Backend Health
Write-Host "1. Backend Health Check..." -ForegroundColor White -NoNewline
try {
    $response = Invoke-WebRequest -Uri "http://localhost:3001/health" -UseBasicParsing -ErrorAction Stop
    if ($response.StatusCode -eq 200) {
        Write-Host " OK" -ForegroundColor Green
        $passed++
    }
} catch {
    Write-Host " FAILED" -ForegroundColor Red
    $failed++
}

# Test 2: Sensor Endpoint
Write-Host "2. Sensor Data Endpoint..." -ForegroundColor White -NoNewline
try {
    $json = @{"protocol"="tcp";"src_ip"="192.168.1.1";"dst_ip"="8.8.8.8";"src_port"=443;"dst_port"=80} | ConvertTo-Json
    $response = Invoke-WebRequest -Uri "http://localhost:3001/api/sensor/data" `
        -Method POST -ContentType "application/json" -Body $json `
        -UseBasicParsing -ErrorAction Stop
    if ($response.StatusCode -eq 201) {
        Write-Host " OK" -ForegroundColor Green
        $passed++
    }
} catch {
    Write-Host " FAILED" -ForegroundColor Red
    $failed++
}

# Test 3: Backend Process
Write-Host "3. Backend Process..." -ForegroundColor White -NoNewline
$nodeProc = Get-Process node -ErrorAction SilentlyContinue
if ($nodeProc) {
    Write-Host " OK" -ForegroundColor Green
    $passed++
} else {
    Write-Host " FAILED" -ForegroundColor Red
    $failed++
}

# Test 4: Sensor Process
Write-Host "4. Sensor Process..." -ForegroundColor White -NoNewline
$sensorProc = Get-Process shadow-sensor -ErrorAction SilentlyContinue
if ($sensorProc) {
    Write-Host " OK" -ForegroundColor Green
    $passed++
} else {
    Write-Host " FAILED" -ForegroundColor Red
    $failed++
}

# Test 5: Port Listening
Write-Host "5. Port 3001 Listening..." -ForegroundColor White -NoNewline
$netstat = netstat -ano 2>$null | Select-String "LISTENING" | Select-String ":3001"
if ($netstat) {
    Write-Host " OK" -ForegroundColor Green
    $passed++
} else {
    Write-Host " FAILED" -ForegroundColor Red
    $failed++
}

Write-Host ""
Write-Host "RESULTS" -ForegroundColor Green
Write-Host "=======" -ForegroundColor Green
Write-Host "Passed: $passed/5" -ForegroundColor Green
Write-Host "Failed: $failed/5" -ForegroundColor Yellow
Write-Host ""

if ($failed -eq 0) {
    Write-Host "All systems operational!" -ForegroundColor Green
} else {
    Write-Host "Some tests failed" -ForegroundColor Yellow
}

Write-Host ""
