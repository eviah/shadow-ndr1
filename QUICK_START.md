# QUICK_START.md

## Shadow NDR System - Quick Start Guide

### 🚀 Fastest Way to Start Everything

```powershell
# Run from project root
powershell -ExecutionPolicy Bypass -File .\run_all.ps1
```

This script will:
1. ✅ Kill any running processes
2. ✅ Start Docker (PostgreSQL + Redis)
3. ✅ Start Backend (http://localhost:3001)
4. ✅ Start Frontend (http://localhost:3000)
5. ✅ Start Sensor (packet capture)
6. ✅ Display all URLs and status

---

## 🔧 Manual Startup (if needed)

### Step 1: Start Database & Cache
```powershell
cd multi-tenant
docker-compose up -d
```

### Step 2: Start Backend
```powershell
cd multi-tenant\backend
npm run dev
# Expect: "🚀 Shadow NDR MT APEX v3.1 LIVE – Sensor endpoint ready"
```

### Step 3: Start Frontend
```powershell
cd multi-tenant\frontend
npm run dev
# Open http://localhost:3000
```

### Step 4: Start Sensor
```powershell
cd shadow-sensor
# IMPORTANT: Run as Administrator
.\target\release\shadow-sensor.exe --health-port 8082 --metrics-port 9091
```

---

## 🧪 Test the API

Before running the sensor, test the Backend API:

```powershell
# Run test script
.\test_api.ps1
```

Or test manually:

```powershell
# Send a test packet
$payload = @{
    protocol = "tcp"
    timestamp = (Get-Date -AsUTC -Format "yyyy-MM-ddTHH:mm:ss.fffZ")
    flow_id = "test_123"
    src_ip = "192.168.1.1"
    dst_ip = "8.8.8.8"
    src_port = 443
    dst_port = 80
    threat_level = "low"
    details = "test"
} | ConvertTo-Json

Invoke-RestMethod -Uri "http://localhost:3001/api/sensor/data" `
    -Method Post `
    -Body $payload `
    -ContentType "application/json"
```

---

## 📊 Service URLs

| Service | URL | Port | Admin |
|---------|-----|------|-------|
| Frontend | http://localhost:3000 | 3000 | - |
| Backend API | http://localhost:3001 | 3001 | - |
| Sensor Health | http://localhost:8082 | 8082 | - |
| Metrics | http://localhost:9091 | 9091 | - |
| PostgreSQL | localhost:5432 | 5432 | shadow_user |
| Redis | localhost:6379 | 6379 | - |

---

## 🔍 Debugging

### Check Backend Logs
```powershell
# Backend window shows real-time logs
# Look for: "Received sensor data", "status: 201", "error: 400"
```

### Check Sensor Logs
```powershell
# Sensor window shows packet capture status
# Look for: "[DEBUG] Sending packet", "✓ Packet sent", "✗ Backend 400"
```

### Enable Debug Logging
```powershell
# Sensor with max debug output
$env:RUST_LOG="debug,shadow_sensor=trace"
.\target\release\shadow-sensor.exe
```

### Common Issues & Fixes

| Issue | Solution |
|-------|----------|
| Port 3001 in use | Kill node: `taskkill /F /IM node.exe` |
| Sensor "admin required" | Run PowerShell as Administrator |
| Docker not found | Install Docker Desktop |
| "400 Bad Request" | Check protocol field in payload |
| "429 Too Many Requests" | Sensor sending too fast (rate limited) |
| Database connection error | Check PostgreSQL is running: `docker-compose ps` |

---

## 📈 Expected Data Flow

```
Sensor captures packets
    ↓
Sensor parses packet data
    ↓
Sensor creates JSON (protocol, timestamp, IPs, ports, etc.)
    ↓
Sensor sends POST to Backend: http://localhost:3001/api/sensor/data
    ↓
Backend validates JSON structure
    ↓
Backend stores in PostgreSQL (threats table)
    ↓
Frontend queries threats from Backend API
    ↓
Frontend displays threats in dashboard
```

---

## 🛠️ Build Commands

### Rebuild Sensor
```powershell
cd shadow-sensor
cargo build --release
```

### Rebuild Backend
```powershell
cd multi-tenant\backend
npm install
npm run build
```

### Rebuild Frontend
```powershell
cd multi-tenant\frontend
npm install
npm run build
```

---

## 🗄️ Database Access

```powershell
# Connect to PostgreSQL
psql -h localhost -U shadow_user -d shadow_ndr

# Query threats table
SELECT * FROM threats LIMIT 10;

# Count threats by protocol
SELECT protocol, COUNT(*) FROM threats GROUP BY protocol;

# Check latest threats
SELECT * FROM threats ORDER BY created_at DESC LIMIT 5;
```

---

## 🚫 Stop Everything

```powershell
# Kill all services
taskkill /F /IM node.exe
taskkill /F /IM shadow-sensor.exe
docker-compose down
```

---

## 📝 Environment Variables

### Backend (.env)
```
DATABASE_URL=postgresql://shadow_user:shadow_password@localhost:5432/shadow_ndr
REDIS_URL=redis://localhost:6379
SENSOR_JWT_SECRET=your_secret_key
FRONTEND_URL=http://localhost:3000
```

### Sensor (environment)
```
RUST_LOG=info,shadow_sensor=debug
BACKEND_URL=http://localhost:3001/api/sensor/data
```

---

## 🎯 Next Steps

1. ✅ Run `.\run_all.ps1` to start all services
2. ✅ Open http://localhost:3000 in browser
3. ✅ Check Backend logs for "Received sensor data"
4. ✅ Query database: `SELECT COUNT(*) FROM threats;`
5. ✅ View threats in Frontend dashboard

---

## 📞 Troubleshooting Checklist

- [ ] Backend listening on port 3001? → `netstat -ano | findstr :3001`
- [ ] Sensor running? → Check sensor window for debug output
- [ ] Database connected? → `docker-compose ps`
- [ ] Redis running? → `redis-cli PING`
- [ ] Correct JSON format? → Run `.\test_api.ps1`
- [ ] Ports available? → Kill old processes with `taskkill`

---

## 🎉 Success Indicators

✅ Backend says: `"[INFO] 🚀 Shadow NDR MT APEX v3.1 LIVE – Sensor endpoint ready"`
✅ Sensor console shows: `"[DEBUG] ✓ Packet sent successfully"`
✅ Backend console shows: `"INFO: Received sensor data"` (repeating)
✅ Frontend displays threats in dashboard
✅ Database contains records: `SELECT COUNT(*) FROM threats` > 0
