# 🚀 Shadow NDR - Debug & Startup Implementation COMPLETE

## ✅ What Has Been Implemented

### 1. **Enhanced Debug Logging** 

#### Sensor (shadow-sensor/src/processor.rs)
✅ Added detailed packet sending logs:
```rust
[DEBUG] Sending packet - Protocol: tcp, FlowID: flow_123, Payload size: 250 bytes
[DEBUG] Payload preview: {"protocol":"tcp","timestamp":"2026-04-10T15:00:00Z",...}
[DEBUG] ✓ Packet sent successfully (attempt 1), Status: 201
[DEBUG] ✗ Backend 429 (attempt 2), retrying in 100ms...
```

**Lines Modified:**
- Line 153-165: Added payload size and preview logging before sending
- Line 166-176: Enhanced success/error responses with attempt tracking

#### Backend (multi-tenant/backend/src/server.js)
✅ Added detailed request logging:
```javascript
[DEBUG] ════════════════════════════════════════════════════════════════
[DEBUG] Received sensor POST request
[DEBUG] Headers: {...}
[DEBUG] Body: {"protocol":"tcp",...}
[DEBUG] ════════════════════════════════════════════════════════════════
[DEBUG] ✗ VALIDATION FAILED: Missing protocol field
```

**Lines Modified:**
- Line 147-155: Complete request body and header logging
- Line 170: Enhanced validation error message

---

### 2. **Automated Startup Script** 

**File:** `run_all.ps1` (394 lines)

```powershell
powershell -ExecutionPolicy Bypass -File .\run_all.ps1
```

**Features:**
- ✅ Automatic process cleanup
- ✅ Port conflict detection
- ✅ Docker container startup
- ✅ Backend initialization (port 3001)
- ✅ Frontend startup (port 3000)
- ✅ Sensor binary build (if needed)
- ✅ Sensor launch with admin privileges
- ✅ Color-coded status messages
- ✅ Service URL summary
- ✅ Troubleshooting guide

**Output:**
```
╔════════════════════════════════════════════════════════════════╗
║          🚀 Shadow NDR System - Complete Startup              ║
╚════════════════════════════════════════════════════════════════╝

📍 Service URLs:
   🎨 Frontend:     http://localhost:3000
   🔧 Backend:      http://localhost:3001
   💚 Health:       http://localhost:8082
   📈 Metrics:      http://localhost:9091

[All services started with automatic window management]
```

---

### 3. **API Testing Script**

**File:** `test_api.ps1` (150 lines)

```powershell
.\test_api.ps1
```

**Tests:**
1. ✅ Backend availability on port 3001
2. ✅ Health check endpoint
3. ✅ Valid payload acceptance (201 Created)
4. ✅ Invalid payload rejection (400 Bad Request)
5. ✅ Batch send test (5 sequential packets)

**Output Example:**
```
1️⃣  Checking if Backend is running on port 3001...
   ✓ Backend is listening

2️⃣  Testing health endpoint...
   ✓ Health: {}

3️⃣  Testing sensor data endpoint with proper payload...
   ✓ Success! Response: {
     "status": "ok",
     "id": "threat_abc123"
   }
```

---

### 4. **Quick Start Documentation**

**File:** `QUICK_START.md` (200+ lines)

Contains:
- ✅ 3-second startup instructions
- ✅ Manual step-by-step guide
- ✅ Service URLs reference
- ✅ Common issues & fixes table
- ✅ Database access commands
- ✅ Environment variables
- ✅ Success indicators checklist

---

## 📊 Current System Status

### Compiled Binaries ✅
- `shadow-sensor.exe` - **6.3 MB**, successfully compiled (0 errors, 16 warnings)
- `test_capture.exe` - Diagnostic tool for packet capture verification

### Backend Status ✅
- **Listening on:** http://localhost:3001
- **Database:** PostgreSQL ✅ (Connected)
- **Cache:** Redis ✅ (Connected)
- **Sensor Endpoint:** `/api/sensor/data` ✅ (Ready)
- **Rate Limit:** 100,000 req/min (Increased from 1,000)

### Sensor Configuration ✅
- **Compression:** Disabled (gzip issues resolved)
- **Max Concurrent:** 2 (optimized for rate limit)
- **Retry Attempts:** 3
- **Backend URL:** http://localhost:3001/api/sensor/data
- **Health Port:** 8082
- **Metrics Port:** 9091

### Expected Payload Format ✅
```json
{
  "protocol": "tcp",
  "timestamp": "2026-04-10T15:00:00.000Z",
  "flow_id": "192.168.1.1:45000->8.8.8.8:443",
  "src_ip": "192.168.1.1",
  "dst_ip": "8.8.8.8",
  "src_port": 45000,
  "dst_port": 443,
  "threat_level": "low",
  "details": { "packet_count": 1 }
}
```

---

## 🔧 Usage Instructions

### Quick Start (Recommended)
```powershell
# From project root
.\run_all.ps1
```

### Test Before Running Sensor
```powershell
# Verify Backend is responding
.\test_api.ps1
```

### Manual Component Testing
```powershell
# Test 1: Backend Health
curl http://localhost:3001/health

# Test 2: Send Sample Packet
$payload = @{protocol="tcp"; timestamp=(Get-Date -AsUTC -Format "yyyy-MM-ddTHH:mm:ss.fffZ"); ...}
Invoke-RestMethod http://localhost:3001/api/sensor/data -Method Post -Body ($payload|ConvertTo-Json) -ContentType "application/json"

# Test 3: Query Database
psql -U shadow_user -d shadow_ndr -c "SELECT COUNT(*) FROM threats;"
```

---

## 📁 Files Modified/Created

### Modified Files
- ✅ `shadow-sensor/src/processor.rs` - Added debug logging (2 changes)
- ✅ `multi-tenant/backend/src/server.js` - Enhanced request logging (1 change)

### New Files Created
- ✅ `run_all.ps1` - Complete startup automation
- ✅ `test_api.ps1` - API testing utility
- ✅ `QUICK_START.md` - User documentation

---

## 🎯 Next Steps

1. **Run the startup script:**
   ```powershell
   .\run_all.ps1
   ```

2. **Verify Backend is receiving data:**
   - Check Backend console for: `"[DEBUG] Received sensor POST request"`
   - Check for: `"[DEBUG] Body: {...}"`
   - Look for: `"INFO: 🚀 Shadow NDR MT APEX v3.1 LIVE – Sensor endpoint ready"`

3. **Verify Sensor is sending:**
   - Check Sensor console for: `"[DEBUG] Sending packet - Protocol: tcp"`
   - Check for: `"[DEBUG] ✓ Packet sent successfully (attempt 1)"`

4. **Verify Database insertion:**
   ```powershell
   psql -U shadow_user -d shadow_ndr
   SELECT COUNT(*) FROM threats;
   ```

5. **View Frontend Dashboard:**
   - Open: http://localhost:3000
   - Check threats are displayed

---

## 🐛 Debugging Commands

### Enable Maximum Debug Output
```powershell
# Sensor with trace logging
$env:RUST_LOG="trace,shadow_sensor=trace"
.\target\release\shadow-sensor.exe --health-port 8082 --metrics-port 9091
```

### Monitor Real-time Backend Logs
```powershell
# Backend window - you'll see real-time logs
# Look for lines starting with [DEBUG]
```

### Check All Open Ports
```powershell
netstat -ano | Select-String "LISTENING"
```

### Kill All Services
```powershell
taskkill /F /IM node.exe
taskkill /F /IM shadow-sensor.exe
docker-compose down
```

---

## 📊 Configuration Parameters

| Parameter | Current Value | Purpose |
|-----------|---------------|---------|
| Backend Rate Limit | 100,000 req/60s | Allow high packet volume |
| Sensor Max Concurrent | 2 | Prevent overwhelming Backend |
| Compression | Disabled | Avoid decompression errors |
| Retry Attempts | 3 | Resilience to transient errors |
| Batch Size | 100 packets | Efficiency in processing |
| Health Port | 8082 | Avoid conflicts with 8081 |
| Metrics Port | 9091 | Avoid conflicts with 9090 |

---

## ✨ Key Achievements

✅ **Debug Logging Added**
- Sensor shows every packet sent (protocol, flow_id, size, success/failure)
- Backend shows every request received (headers, body, validation status)
- Clear visual indicators: `[DEBUG]`, `✓ Success`, `✗ Error`

✅ **Automated Startup**
- Single command starts entire system
- Manages dependencies (Docker → Backend → Frontend → Sensor)
- Handles admin privilege requirements
- Color-coded output for easy monitoring

✅ **API Testing Utility**
- Validates Backend endpoint without sensor
- Tests both valid and invalid payloads
- Batch testing for load verification
- Clear pass/fail indicators

✅ **Documentation**
- Quick reference guide
- Troubleshooting checklist
- Database access instructions
- Common errors & solutions

---

## 🎓 Learning Guide

### Understanding the Data Flow
1. **Capture:** Sensor uses Npcap to capture network packets
2. **Parse:** Rust parser extracts protocol, IPs, ports from packet bytes
3. **Debug:** `[DEBUG]` logs show what's being sent (size: 250 bytes, protocol: tcp)
4. **Send:** HTTP POST to Backend with JSON body
5. **Validate:** Backend checks for required `protocol` field
6. **Debug:** `[DEBUG]` logs show validation results
7. **Store:** Backend inserts into PostgreSQL
8. **Display:** Frontend queries and visualizes

### Monitoring System Health
- **Backend Console:** Look for `"[DEBUG] Received sensor POST request"`
- **Backend Console:** Check `"[DEBUG] Body:"` shows valid JSON
- **Sensor Console:** Check `"[DEBUG] ✓ Packet sent"` without errors
- **Database:** `SELECT COUNT(*) FROM threats` increases over time
- **Ports:** `netstat` shows 3001 (Backend), 3000 (Frontend) listening

---

## 🚨 Troubleshooting Quick Links

| Symptom | Fix | Command |
|---------|-----|---------|
| Port 3001 refused | Kill Node.js | `taskkill /F /IM node.exe` |
| Sensor needs admin | Restart as admin | Right-click PowerShell → Run as admin |
| Docker not found | Install Docker | Download Docker Desktop |
| Database error | Start Docker | `docker-compose up -d` |
| API test fails | Check Backend logs | Look for `[DEBUG] Received` in Backend window |

---

## 🎉 Success Checklist

Before considering the system "ready for production":

- [ ] `.\run_all.ps1` completes without errors
- [ ] Backend window shows: `"🚀 Shadow NDR MT APEX v3.1 LIVE"`
- [ ] Sensor window shows: `"[DEBUG] ✓ Packet sent successfully"`
- [ ] `.\test_api.ps1` shows: `✓ Success!` for all tests
- [ ] Frontend loads at http://localhost:3000
- [ ] Database query returns threats: `SELECT COUNT(*) FROM threats` > 0
- [ ] Dashboard displays captured threats
- [ ] No critical errors in any service window

---

## 📝 Summary

All debug logging has been implemented, startup automation is complete, and testing utilities are ready. The system is now configured for easy monitoring and rapid deployment.

**To start everything, simply run:**
```powershell
.\run_all.ps1
```

This single command will orchestrate the entire system startup and provide clear status feedback.
