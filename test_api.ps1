# test_api.ps1
# Test the Backend API with proper payload format

Write-Host "🧪 Testing Shadow NDR Backend API" -ForegroundColor Cyan
Write-Host "═══════════════════════════════════════════════════════════`n" -ForegroundColor Cyan

# Check if backend is running
Write-Host "1️⃣  Checking if Backend is running on port 3001..." -ForegroundColor Yellow
$backendTest = netstat -ano 2>$null | Select-String "LISTENING" | Select-String ":3001\s"
if ($backendTest) {
    Write-Host "   ✓ Backend is listening" -ForegroundColor Green
} else {
    Write-Host "   ✗ Backend NOT running - start with: npm run dev" -ForegroundColor Red
    exit 1
}

# Test 1: Health check
Write-Host "`n2️⃣  Testing health endpoint..." -ForegroundColor Yellow
try {
    $health = Invoke-RestMethod -Uri "http://localhost:3001/health" -Method Get -ErrorAction Stop
    Write-Host "   ✓ Health: $(($health | ConvertTo-Json))" -ForegroundColor Green
} catch {
    Write-Host "   ✗ Health check failed: $($_.Exception.Message)" -ForegroundColor Yellow
}

# Test 2: Send proper JSON payload
Write-Host "`n3️⃣  Testing sensor data endpoint with proper payload..." -ForegroundColor Yellow

$payload = @{
    protocol = "tcp"
    timestamp = (Get-Date -AsUTC -Format "yyyy-MM-ddTHH:mm:ss.fffZ")
    flow_id = "test_flow_123"
    src_ip = "192.168.1.100"
    dst_ip = "8.8.8.8"
    src_port = 45123
    dst_port = 443
    threat_level = "low"
    details = @{
        packet_count = 1
        bytes_sent = 1024
        direction = "outbound"
    }
} | ConvertTo-Json

Write-Host "   Payload:" -ForegroundColor Gray
Write-Host $payload | ForEach-Object { "     $_" } -ForegroundColor Gray

Write-Host "`n   Sending..." -ForegroundColor Yellow
try {
    $response = Invoke-RestMethod -Uri "http://localhost:3001/api/sensor/data" `
        -Method Post `
        -Body $payload `
        -ContentType "application/json" `
        -ErrorAction Stop
    
    Write-Host "   ✓ Success! Response:" -ForegroundColor Green
    Write-Host "     $(($response | ConvertTo-Json))" -ForegroundColor Green
} catch {
    if ($_.Exception.Response) {
        $reader = New-Object System.IO.StreamReader($_.Exception.Response.GetResponseStream())
        $reader.BaseStream.Position = 0
        $reader.DiscardBufferedData()
        $errBody = $reader.ReadToEnd()
        Write-Host "   ✗ Error (Status: $($_.Exception.Response.StatusCode))" -ForegroundColor Red
        Write-Host "     Response: $errBody" -ForegroundColor Red
    } else {
        Write-Host "   ✗ Error: $($_.Exception.Message)" -ForegroundColor Red
    }
}

# Test 3: Invalid payload (missing protocol)
Write-Host "`n4️⃣  Testing validation (should fail - missing protocol)..." -ForegroundColor Yellow

$invalidPayload = @{
    timestamp = (Get-Date -AsUTC -Format "yyyy-MM-ddTHH:mm:ss.fffZ")
    flow_id = "test_flow_456"
    src_ip = "192.168.1.101"
    dst_ip = "1.1.1.1"
} | ConvertTo-Json

try {
    $response = Invoke-RestMethod -Uri "http://localhost:3001/api/sensor/data" `
        -Method Post `
        -Body $invalidPayload `
        -ContentType "application/json" `
        -ErrorAction Stop
    
    Write-Host "   ⚠️  Unexpected success (should have failed)" -ForegroundColor Yellow
} catch {
    if ($_.Exception.Response.StatusCode -eq "BadRequest") {
        Write-Host "   ✓ Correctly rejected invalid payload (400 Bad Request)" -ForegroundColor Green
    } else {
        Write-Host "   ? Got status: $($_.Exception.Response.StatusCode)" -ForegroundColor Yellow
    }
}

# Test 4: Batch test
Write-Host "`n5️⃣  Testing batch send (5 packets)..." -ForegroundColor Yellow
for ($i = 1; $i -le 5; $i++) {
    $batchPayload = @{
        protocol = "tcp"
        timestamp = (Get-Date -AsUTC -Format "yyyy-MM-ddTHH:mm:ss.fffZ")
        flow_id = "batch_$i"
        src_ip = "192.168.1.$i"
        dst_ip = "8.8.4.4"
        src_port = (45000 + $i)
        dst_port = 80
        threat_level = if ($i -gt 3) { "medium" } else { "low" }
        details = @{ batch = $i }
    } | ConvertTo-Json
    
    try {
        $response = Invoke-RestMethod -Uri "http://localhost:3001/api/sensor/data" `
            -Method Post `
            -Body $batchPayload `
            -ContentType "application/json" `
            -ErrorAction Stop
        Write-Host "   ✓ Packet $i: Success (Status: 201)" -ForegroundColor Green
    } catch {
        Write-Host "   ✗ Packet $i: $($_.Exception.Response.StatusCode)" -ForegroundColor Red
    }
    
    Start-Sleep -Milliseconds 100
}

Write-Host "`n✅ API Testing Complete!`n" -ForegroundColor Cyan
Write-Host "💡 Next: Start sensor with: .\run_all.ps1`n" -ForegroundColor Yellow
