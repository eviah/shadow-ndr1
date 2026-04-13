# 🚀 Shadow NDR Sensor - Copy-Paste Commands

All commands you need to launch the system. Just copy and paste into separate PowerShell windows.

---

## ⚡ FASTEST WAY (Copy-paste each line to a new PowerShell window)

### 🖥️ Window 1: Start Docker Services
```powershell
cd C:\Users\liorh\shadow-ndr\multi-tenant; docker-compose up -d
```

### 🖥️ Window 2: Start Backend API
```powershell
cd C:\Users\liorh\shadow-ndr\multi-tenant\backend; npm run dev
```

### 🖥️ Window 3: Start Frontend
```powershell
cd C:\Users\liorh\shadow-ndr\multi-tenant\frontend; npm run dev
```

### 🖥️ Window 4: Start Sensor (⚠️ RUN AS ADMINISTRATOR)
```powershell
cd C:\Users\liorh\shadow-ndr\shadow-sensor; .\target\release\shadow-sensor.exe
```

### 🖥️ Window 5: Start ML Simulator (Optional)
```powershell
cd C:\Users\liorh\shadow-ndr\shadow-ml; python auto_threat_simulator.py
```

---

## ✅ VERIFICATION COMMANDS

Run these in any PowerShell window to verify everything is working:

```powershell
# Check sensor is responding
curl http://localhost:8081/health

# Check metrics
curl http://localhost:9090/metrics

# Check backend API
curl http://localhost:3001/api/threats

# Check Docker containers
docker ps
```

---

## 🔧 ALTERNATIVE LAUNCH OPTIONS

### With Interface Selection
```powershell
# List available interfaces
cd C:\Users\liorh\shadow-ndr\shadow-sensor; .\target\release\shadow-sensor.exe --list-interfaces

# Launch with specific interface (replace {GUID})
.\target\release\shadow-sensor.exe --interfaces "\Device\NPF_{YOUR_GUID}"
```

### With BPF Filter
```powershell
# Only capture TCP and UDP
cd C:\Users\liorh\shadow-ndr\shadow-sensor; .\target\release\shadow-sensor.exe --bpf-filter "tcp or udp"

# Only capture on port 443
.\target\release\shadow-sensor.exe --bpf-filter "port 443"
```

### Backend with Environment Variables
```powershell
cd C:\Users\liorh\shadow-ndr\multi-tenant\backend
$env:DATABASE_URL="postgresql://postgres:postgres@localhost:5432/shadow"
$env:REDIS_URL="redis://localhost:6379"
npm run dev
```

---

## 🧹 CLEANUP COMMANDS

### Stop Everything Gracefully
```powershell
# In each window, press Ctrl+C

# Then stop Docker
cd C:\Users\liorh\shadow-ndr\multi-tenant
docker-compose down
```

### Kill All Services (Force)
```powershell
# Kill Node.js
Stop-Process -Name node -Force

# Stop Docker containers
docker stop $(docker ps -q)
```

### Full Clean (if needed)
```powershell
cd C:\Users\liorh\shadow-ndr\shadow-sensor
cargo clean
cargo build --release
```

---

## 📊 MONITORING COMMANDS

### Watch Sensor Metrics (Real-time)
```powershell
while($true) {
    curl -s http://localhost:9090/metrics | Select-String "shadow_"
    Start-Sleep 2
    Clear-Host
}
```

### Watch Docker Logs
```powershell
docker-compose logs -f
```

### Watch Backend Health
```powershell
while($true) {
    curl -s http://localhost:3001/api/health
    Start-Sleep 5
}
```

### List Running Processes
```powershell
Get-Process | Where-Object {$_.ProcessName -match "(node|docker|shadow)" }
```

---

## 🆘 TROUBLESHOOTING COMMANDS

### Check if Ports Are In Use
```powershell
# Check port 3001 (Backend)
netstat -ano | Select-String "3001"

# Check port 3000 (Frontend)
netstat -ano | Select-String "3000"

# Check port 8081 (Sensor)
netstat -ano | Select-String "8081"
```

### Kill Process on Port
```powershell
# Replace 3001 with your port
$pid = (netstat -ano | Select-String "3001").Split()[-1]
Stop-Process -Id $pid -Force
```

### Check Npcap Installation
```powershell
Test-Path "C:\Windows\System32\wpcap.dll"
```

### Reinstall Npcap (if needed)
```powershell
# Manual install from:
# https://npcap.com/dist/npcap-1.81.exe
```

### View Docker Container Logs
```powershell
# PostgreSQL logs
docker logs multi-tenant-postgres-1

# Redis logs
docker logs multi-tenant-redis-1

# All services
docker-compose logs
```

---

## 🎯 TEST THE SYSTEM

### Minimal Test
```powershell
# After all services running
curl http://localhost:8081/health     # Should return OK
curl http://localhost:3001/api/health # Should return OK
```

### Full System Test (from repo root)
```powershell
cd C:\Users\liorh\shadow-ndr
powershell .\test-system.ps1
```

### API Tests
```powershell
# Get all threats
curl http://localhost:3001/api/threats

# Get specific metric
curl http://localhost:3001/api/metrics

# Get packet statistics
curl http://localhost:3001/api/packets
```

---

## 📝 LOGGING IN TO FRONTEND

Default credentials (if authentication is enabled):
```
Username: admin
Password: admin
```

Or check backend `.env` file for credentials.

---

## 🌐 QUICK ACCESS LINKS

After everything is running, open these in your browser:

```
Frontend:      http://localhost:3000
Backend API:   http://localhost:3001
Sensor Health: http://localhost:8081/health
Metrics:       http://localhost:9090/metrics
Swagger UI:    http://localhost:3001/api/docs (if available)
```

---

## 💡 TIPS & TRICKS

### Use WSL2 Terminal for Better Experience
```powershell
# If you have WSL2, you can use:
wsl -e bash -c "cd /mnt/c/Users/liorh/shadow-ndr && ls"
```

### Set PowerShell Execution Policy (if needed)
```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

### Run Multiple Commands in One Window
```powershell
cd C:\Users\liorh\shadow-ndr\multi-tenant; docker-compose up -d; Start-Sleep 2; cd ../multi-tenant/backend; npm run dev
```

### Create PowerShell Shortcut for Quick Launch
```powershell
# Create shortcut pointing to:
# powershell -NoExit -Command "cd C:\Users\liorh\shadow-ndr\multi-tenant\backend; npm run dev"
```

---

## 🎓 LEARNING THE SYSTEM

### View Source Code
```powershell
# Sensor code
code C:\Users\liorh\shadow-ndr\shadow-sensor

# Backend code
code C:\Users\liorh\shadow-ndr\multi-tenant\backend

# Frontend code
code C:\Users\liorh\shadow-ndr\multi-tenant\frontend
```

### Read Configuration Files
```powershell
# Sensor config
notepad C:\Users\liorh\shadow-ndr\shadow-sensor\config.yaml

# Backend env
notepad C:\Users\liorh\shadow-ndr\multi-tenant\backend\.env

# Docker compose
notepad C:\Users\liorh\shadow-ndr\multi-tenant\docker-compose.yml
```

---

**Last Updated**: April 7, 2026
**Status**: Ready to Deploy ✅
