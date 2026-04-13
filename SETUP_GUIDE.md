# 🛡️ Shadow NDR System - Complete Setup & Operation Guide

## 📌 Overview

Shadow NDR (Network Detection and Response) is a real-time threat detection system that:
- 🔍 Captures live network packets using Npcap
- 📊 Parses packets and extracts threat indicators  
- 📤 Sends to Backend API for processing
- 🗄️ Stores in PostgreSQL database
- 🎨 Visualizes threats in web dashboard

---

## 🚀 30-Second Quick Start

```powershell
# From project root (C:\Users\liorh\shadow-ndr)
powershell -ExecutionPolicy Bypass -File .\run_all.ps1
```

**This will automatically:**
1. ✅ Stop any existing processes
2. ✅ Start PostgreSQL + Redis (Docker)
3. ✅ Start Backend API (port 3001)
4. ✅ Start Frontend (port 3000)
5. ✅ Start Sensor (packet capture)
6. ✅ Display all service URLs

---

## 📚 Prerequisites

### Required
- ✅ Windows 10/11
- ✅ Docker Desktop (for PostgreSQL + Redis)
- ✅ Node.js 18+ (npm)
- ✅ Rust toolchain (already installed, `cargo` available)
- ✅ Npcap driver (packet capture library)
- ✅ PowerShell 5.0+

### Verify Installation
```powershell
# Check Node.js
node --version   # Should show v18+
npm --version    # Should show 9+

# Check Rust
cargo --version  # Should show latest

# Check Docker
docker --version # Should show Docker version

# Check Npcap
Get-Service npcap -ErrorAction SilentlyContinue | Select Status
```

---

## 🏗️ System Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                   SHADOW NDR SYSTEM                         │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  SENSOR LAYER                                              │
│  ────────────                                              │
│  ┌─────────────────────────────────────────────────────┐  │
│  │ shadow-sensor (Rust)                                │  │
│  │ • Npcap packet capture                             │  │
│  │ • Protocol parsing (TCP/UDP/DNS/TLS)               │  │
│  │ • Threat detection rules                           │  │
│  │ • Async Tokio runtime (9 worker threads)          │  │
│  └─────────────────────────────────────────────────────┘  │
│                        │                                   │
│                        │ POST JSON                         │
│                        ▼                                   │
│  BACKEND LAYER                                             │
│  ─────────────                                             │
│  ┌─────────────────────────────────────────────────────┐  │
│  │ multi-tenant/backend (Node.js/Express)             │  │
│  │ • API endpoint: /api/sensor/data                    │  │
│  │ • Rate limiting (100k req/min)                      │  │
│  │ • JWT authentication (optional)                     │  │
│  │ • Database ingestion                               │  │
│  └─────────────────────────────────────────────────────┘  │
│                        │                                   │
│         ┌──────────────┼──────────────┐                    │
│         ▼              ▼              ▼                    │
│  ┌─────────────┐ ┌──────────┐ ┌─────────────┐            │
│  │ PostgreSQL  │ │  Redis   │ │   Kafka     │            │
│  │ (Threats)   │ │(Sessions)│ │ (Queues)    │            │
│  └─────────────┘ └──────────┘ └─────────────┘            │
│                        │                                   │
│                        │ GraphQL/REST                      │
│                        ▼                                   │
│  FRONTEND LAYER                                            │
│  ──────────────                                            │
│  ┌─────────────────────────────────────────────────────┐  │
│  │ multi-tenant/frontend (React)                       │  │
│  │ • Dashboard visualization                          │  │
│  │ • Real-time threat updates (Socket.IO)             │  │
│  │ • Threat filtering & search                        │  │
│  │ • Network topology map                             │  │
│  └─────────────────────────────────────────────────────┘  │
│         ▲                                                  │
│         │ http://localhost:3000                           │
│         │                                                  │
│    USER BROWSER                                            │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

---

## 🔧 Manual Setup (Step by Step)

### Step 1: Start Database Services
```powershell
cd C:\Users\liorh\shadow-ndr\multi-tenant
docker-compose up -d
```

**Verify:**
```powershell
docker-compose ps
# Should show: postgresql (Up), redis (Up)
```

### Step 2: Start Backend API
```powershell
cd C:\Users\liorh\shadow-ndr\multi-tenant\backend
npm install  # First time only
npm run dev
```

**Look for:**
```
[HH:MM:SS] INFO: 🚀 Shadow NDR MT APEX v3.1 LIVE – Sensor endpoint ready
[HH:MM:SS] INFO: port: 3001
```

### Step 3: Start Frontend
```powershell
cd C:\Users\liorh\shadow-ndr\multi-tenant\frontend
npm install  # First time only
npm run dev
```

**Look for:**
```
VITE v4.x.x build ready
➜ Local: http://localhost:3000/
```

### Step 4: Start Sensor (Admin Required)
```powershell
# Right-click PowerShell → "Run as Administrator"
cd C:\Users\liorh\shadow-ndr\shadow-sensor

# Build (first time)
cargo build --release  # ~3 min

# Run
$env:RUST_LOG="info,shadow_sensor=debug"
.\target\release\shadow-sensor.exe --health-port 8082 --metrics-port 9091
```

**Look for:**
```
[DEBUG] Sending packet - Protocol: tcp, FlowID: ..., Payload size: ...
[DEBUG] ✓ Packet sent successfully (attempt 1), Status: 201
```

---

## 🧪 Testing the System

### Quick Health Check
```powershell
# Backend health
curl http://localhost:3001/health

# Sensor health
curl http://localhost:8082/health

# Metrics
curl http://localhost:9091/metrics
```

### Test API Endpoint
```powershell
.\test_api.ps1
```

**Expected output:**
```
✓ Backend is listening
✓ Health: {}
✓ Success! Response: {"status":"ok","id":"threat_123"}
✓ Correctly rejected invalid payload (400 Bad Request)
✓ Packet 1: Success (Status: 201)
...
```

### Test Database
```powershell
# Access PostgreSQL
psql -h localhost -U shadow_user -d shadow_ndr

# Count threats
SELECT COUNT(*) FROM threats;
# Should return growing numbers as sensor runs

# View latest threats
SELECT protocol, src_ip, dst_ip, threat_level FROM threats 
ORDER BY created_at DESC LIMIT 5;
```

---

## 📊 Service Endpoints

| Service | URL | Port | Purpose |
|---------|-----|------|---------|
| **Frontend** | http://localhost:3000 | 3000 | Web dashboard |
| **Backend API** | http://localhost:3001 | 3001 | Sensor ingestion |
| **Backend Health** | http://localhost:3001/health | 3001 | Service status |
| **Sensor Health** | http://localhost:8082 | 8082 | Packet capture status |
| **Metrics** | http://localhost:9091 | 9091 | Prometheus metrics |
| **PostgreSQL** | localhost:5432 | 5432 | Database |
| **Redis** | localhost:6379 | 6379 | Cache/sessions |

---

## 🔍 Monitoring & Debugging

### View Backend Logs
```powershell
# Real-time (running in console)
# Look for "[DEBUG] Received sensor POST request"

# Or check persistent log
Get-Content C:\Users\liorh\shadow-ndr\multi-tenant\backend\backend.log -Tail 50
```

### View Sensor Logs
```powershell
# Real-time in sensor window
# Enable debug: $env:RUST_LOG="debug,shadow_sensor=trace"

# Check for patterns:
# "[DEBUG] Sending packet" = packet being sent
# "[DEBUG] ✓ Packet sent" = success
# "[DEBUG] ✗ Backend 4XX" = API error
```

### Check Running Processes
```powershell
Get-Process | Where-Object {$_.ProcessName -match "node|shadow|postgres|redis"}
```

### Monitor Packet Flow
```powershell
# Terminal 1: Monitor Backend logs
Get-Content "C:\Users\liorh\shadow-ndr\multi-tenant\backend\backend.log" -Tail 0 -Wait

# Terminal 2: Check database growth
while ($true) { 
    psql -U shadow_user -d shadow_ndr -c "SELECT COUNT(*) FROM threats;"
    Start-Sleep 5
}

# Terminal 3: Check sensor captures
# [Check sensor window for [DEBUG] messages]
```

---

## 🚫 Stopping Services

### Stop All Services
```powershell
# Kill processes
taskkill /F /IM node.exe 2>$null
taskkill /F /IM shadow-sensor.exe 2>$null

# Stop Docker
docker-compose down

# Verify
netstat -ano | Select-String "LISTENING" | Select-String "3000|3001|5432"
# Should return empty
```

### Stop Specific Service
```powershell
# Frontend
taskkill /F /IM node.exe  # Stops all node processes

# Backend
# Use same command (both are Node.js) OR close the window

# Sensor
# Close the PowerShell window OR Ctrl+C

# Docker
cd multi-tenant
docker-compose stop
```

---

## 🐛 Common Issues & Solutions

| Issue | Symptom | Solution |
|-------|---------|----------|
| **Port 3001 in use** | "Address already in use" | `taskkill /F /IM node.exe` |
| **Sensor needs admin** | "Access denied" for Npcap | Run PowerShell as Administrator |
| **Docker not found** | "docker-compose: command not found" | Install Docker Desktop |
| **Backend connection refused** | Invoke-RestMethod fails | Check Backend window for errors |
| **400 Bad Request** | Sensor gets validation error | Check protocol field in JSON |
| **429 Too Many Requests** | Rate limited responses | Sensor concurrency too high |
| **Database unreachable** | PostgreSQL connection error | `docker-compose ps` to check |
| **Sensor not sending** | No packets captured | Check Npcap driver: `getmac` |

---

## 🔐 Security Configuration

### Environment Variables (Backend)
```bash
# .env file in multi-tenant/backend/
DATABASE_URL=postgresql://shadow_user:shadow_password@localhost:5432/shadow_ndr
REDIS_URL=redis://localhost:6379
SENSOR_JWT_SECRET=your_secret_key_here  # If enabling JWT
FRONTEND_URL=http://localhost:3000
NODE_ENV=development
```

### Firewall Rules
```powershell
# Allow sensor traffic (if firewall-protected)
netsh advfirewall firewall add rule name="Shadow Sensor" dir=out action=allow program="C:\Users\liorh\shadow-ndr\shadow-sensor\target\release\shadow-sensor.exe"
```

---

## 📈 Performance Tuning

### Optimize Sensor
```powershell
# Increase packet batch size (balance memory vs latency)
.\target\release\shadow-sensor.exe --batch-size 200

# Adjust concurrent sends (balance throughput vs rate limiting)
# Edit config.rs: max_concurrent_sends: 2-10 (test your rate limit)

# Enable compression (reduce payload size)
.\target\release\shadow-sensor.exe --compression-enabled
```

### Optimize Backend
```javascript
// Edit middleware/index.js to increase rate limit
max: 500000  // Up to 500k requests/min
```

### Database Optimization
```sql
-- Create index on threats table
CREATE INDEX idx_threats_timestamp ON threats(created_at DESC);
CREATE INDEX idx_threats_protocol ON threats(protocol);
CREATE INDEX idx_threats_severity ON threats(threat_level);

-- Verify indexes
\d threats  -- Show table structure
\di         -- Show indexes
```

---

## 📝 Logs Location

| Component | Log Path | Type |
|-----------|----------|------|
| **Backend** | `multi-tenant/backend/backend.log` | Persistent |
| **Sensor** | Console window | Real-time |
| **Database** | Docker logs | `docker logs shadow_ndr_postgres` |
| **Frontend** | Browser console (F12) | Client-side |

---

## 🎯 Expected Data Flow

1. **Packet Capture** (Sensor)
   ```
   Npcap → Raw bytes → Parser → ParsedPacket struct
   ```

2. **Serialization** (Sensor)
   ```
   ParsedPacket → serde_json → JSON bytes → HTTP POST
   ```

3. **Transmission** (Sensor → Backend)
   ```
   POST http://localhost:3001/api/sensor/data
   Content-Type: application/json
   Body: {"protocol":"tcp","timestamp":"...","..."}
   ```

4. **Validation** (Backend)
   ```
   Receive JSON → Parse → Validate required fields → Check protocol exists
   ```

5. **Storage** (Backend → Database)
   ```
   Validated data → INSERT INTO threats → PostgreSQL
   ```

6. **Visualization** (Frontend)
   ```
   SELECT * FROM threats → Query API → Render dashboard → Display threats
   ```

---

## 📞 Support & Troubleshooting

### Get System Information
```powershell
# CPU cores
(Get-WmiObject –class Win32_Processor).NumberOfLogicalProcessors

# RAM available
[math]::Round((Get-CimInstance Win32_OperatingSystem).FreePhysicalMemory / 1MB)

# Disk space
Get-Volume C | Select-Object SizeRemaining, Size

# Network interfaces
ipconfig /all
```

### Detailed Diagnostics
```powershell
# Check Windows Defender firewall
netsh advfirewall show allprofiles

# Monitor network connections
netstat -ano | Select-String "3001|3000|5432"

# Check process resources
Get-Process | Where-Object {$_.ProcessName -match "node|shadow"} | Select-Object Name, CPU, Memory
```

### Enable Maximum Debug Output
```powershell
# Sensor (trace level)
$env:RUST_LOG="trace,shadow_sensor=trace"
.\target\release\shadow-sensor.exe

# Backend (if needed)
NODE_ENV=development npm run dev
```

---

## ✅ Success Criteria

The system is working correctly when:

- ✅ All 4 service windows show no errors
- ✅ Backend logs: `"🚀 Shadow NDR MT APEX v3.1 LIVE"`
- ✅ Sensor logs: `"[DEBUG] ✓ Packet sent successfully"`
- ✅ Frontend loads at http://localhost:3000
- ✅ Database has threats: `SELECT COUNT(*) FROM threats` > 0
- ✅ Dashboard displays captured threats
- ✅ No API errors (check Backend window for [DEBUG] messages)

---

## 🎓 Learning Resources

### Understanding the Code
- **Sensor:** `/shadow-sensor/src/main.rs` - Entry point
- **Packet Parsing:** `/shadow-sensor/src/parser.rs` - Protocol parsing
- **HTTP Client:** `/shadow-sensor/src/processor.rs` - Backend communication
- **Backend Routes:** `/multi-tenant/backend/src/routes/threats.js` - API logic
- **Database:** `/multi-tenant/backend/src/services/database.js` - PostgreSQL interface

### Key Concepts
1. **Npcap:** Windows driver for packet capture (like tcpdump/libpcap)
2. **Tokio:** Rust async runtime for concurrent packet processing
3. **Express.js:** Node.js framework for HTTP API
4. **PostgreSQL:** SQL database for storing threats
5. **Redis:** In-memory cache for sessions and rate limiting

---

## 📋 Quick Reference

### Essential Commands

**Start everything:**
```powershell
.\run_all.ps1
```

**Test API:**
```powershell
.\test_api.ps1
```

**Stop everything:**
```powershell
taskkill /F /IM node.exe; taskkill /F /IM shadow-sensor.exe; docker-compose down
```

**View Backend logs:**
```powershell
Get-Content backend\backend.log -Tail 50 -Wait
```

**Query database:**
```powershell
psql -U shadow_user -d shadow_ndr -c "SELECT * FROM threats LIMIT 5;"
```

**Rebuild sensor:**
```powershell
cd shadow-sensor; cargo build --release
```

---

## 🎉 You're Ready!

The system is fully configured and ready to use. Simply run:

```powershell
.\run_all.ps1
```

Then open http://localhost:3000 in your browser to see the threat dashboard.

**Happy monitoring! 🛡️**
