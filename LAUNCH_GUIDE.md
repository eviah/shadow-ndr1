# 🚀 Shadow NDR Sensor - Launch Guide

## ✅ Build Status
- **Binary**: `target\release\shadow-sensor.exe` ✅ (3.94 MB)
- **Compilation**: Successful
- **Dependencies**: All resolved

---

## 📋 Prerequisites

### Required
1. **Npcap** - Network packet capture library
   - Download: https://npcap.com/dist/npcap-1.81.exe
   - **Important**: Install with "WinPcap API-compatible Mode" enabled
   - Requires Administrator privileges

2. **Docker** - For PostgreSQL & Redis
   ```powershell
   # Check if Docker is running
   docker ps
   ```

3. **Node.js 18+** - For backend and frontend
   ```powershell
   node --version
   npm --version
   ```

### Optional
- **Ollama** - For ML threat detection (https://ollama.ai)
- **Python 3.10+** - For threat simulator

---

## 🎯 Quick Start (in order)

### Window 1: Database & Cache (Docker)
```powershell
cd C:\Users\liorh\shadow-ndr\multi-tenant
docker-compose up -d

# Verify
docker ps
```

### Window 2: Backend API (Node.js)
```powershell
cd C:\Users\liorh\shadow-ndr\multi-tenant\backend
npm run dev
```
📍 Runs on: `http://localhost:3001`

### Window 3: Frontend (React)
```powershell
cd C:\Users\liorh\shadow-ndr\multi-tenant\frontend
npm run dev
```
📍 Runs on: `http://localhost:3000`

### Window 4: Sensor (⚠️ Must run as Administrator)
```powershell
# IMPORTANT: Run PowerShell as Administrator for this window!
cd C:\Users\liorh\shadow-ndr\shadow-sensor

# Option A: Auto-detect all interfaces
.\target\release\shadow-sensor.exe

# Option B: Specific interface (replace {YOUR_GUID})
.\target\release\shadow-sensor.exe --interfaces "\Device\NPF_{YOUR_GUID}"

# Option C: With options
.\target\release\shadow-sensor.exe --promisc true --bpf-filter "tcp or udp"
```
📍 Health: `http://localhost:8081/health`
📍 Metrics: `http://localhost:9090/metrics`

### Window 5: ML Engine (Optional)
```powershell
cd C:\Users\liorh\shadow-ndr\shadow-ml

# Install dependencies (one time)
pip install -r requirements.txt

# Start Ollama (in separate terminal)
ollama serve

# In this window, run the simulator
python auto_threat_simulator.py
```

---

## 🔍 Testing the System

### 1. Health Checks
```powershell
# Sensor health
curl http://localhost:8081/health

# Backend health
curl http://localhost:3001/api/health

# Metrics
curl http://localhost:9090/metrics
```

### 2. API Endpoints
```powershell
# Get threats
curl http://localhost:3001/api/threats

# Get packets
curl http://localhost:3001/api/packets

# Get metrics
curl http://localhost:3001/api/metrics
```

### 3. Web Interface
- Frontend: http://localhost:3000
- Backend API: http://localhost:3001
- Health: http://localhost:8081/health

---

## 🛠️ Troubleshooting

### Problem: "Administrator privileges required"
**Solution**: Right-click PowerShell → "Run as administrator"

### Problem: "Interface not found"
**Solution**: List available interfaces:
```powershell
cd C:\Users\liorh\shadow-ndr\shadow-sensor
.\target\release\shadow-sensor.exe --list-interfaces
```

### Problem: "wpcap.lib not found"
**Solution**: 
1. Uninstall Npcap from Control Panel
2. Download from: https://npcap.com/dist/npcap-1.81.exe
3. **Ensure** "WinPcap API-compatible Mode" is checked during installation
4. Restart computer

### Problem: "Port already in use"
**Solution**:
```powershell
# Kill process using port 3001
Stop-Process -Name node -Force

# Kill process using port 8081
Get-Process | Where-Object {$_.Handles -gt 1000} | Stop-Process
```

### Problem: Backend not responding
**Solution**:
```powershell
# Check Docker
docker ps

# Restart services
cd C:\Users\liorh\shadow-ndr\multi-tenant
docker-compose down
docker-compose up -d

# Check logs
docker-compose logs
```

---

## 📊 Monitoring

### View Sensor Logs
```powershell
# In the sensor window, watch for:
# - "Capture engine running on X interface(s)"
# - "Packets processed: XXX"
# - Any error messages
```

### View Backend Logs
```powershell
# The npm run dev window shows:
# - Incoming API requests
# - Database queries
# - Error messages
```

### View Metrics
```powershell
# Prometheus endpoint
curl http://localhost:9090/metrics | Select-String "shadow_"
```

---

## 📈 Expected Output

### Sensor Window (should show):
```
✅ Capture engine running on 2 interface(s)
📊 Packet processing started
🔌 Health endpoint: http://0.0.0.0:8081/health
📈 Metrics endpoint: http://0.0.0.0:9090/metrics
```

### Backend Window (should show):
```
Server running on http://localhost:3001
Connected to PostgreSQL
Redis cache initialized
```

### Frontend Window (should show):
```
➜  Local: http://localhost:3000/
➜  press h to show help
```

---

## 🎮 Using the System

### 1. Open Frontend
Visit: http://localhost:3000

### 2. Monitor Network
- Real-time threat detection
- Packet statistics
- Protocol breakdown

### 3. Check Metrics
Visit: http://localhost:9090/metrics
Look for metrics like:
- `shadow_packets_processed_total`
- `shadow_batch_process_duration_seconds`
- `shadow_protocols_tcp_total`

### 4. Run Threat Simulation (Optional)
```powershell
cd C:\Users\liorh\shadow-ndr\shadow-ml
python auto_threat_simulator.py
```

---

## ⚙️ Configuration

### Sensor Config (config.yaml)
Located in: `shadow-sensor/config.yaml`

Key settings:
```yaml
interfaces: []  # Empty = auto-detect all
promisc: true   # Promiscuous mode
snaplen: 65535  # Capture full packet
batch_size: 100 # Batch processing size
rate_limit_pps: 0  # 0 = unlimited
backend_url: "http://localhost:3001/api/packets"
```

---

## 🚨 Emergency Stop

To stop all services:
```powershell
# Stop sensor (Ctrl+C in sensor window)
# Stop backend (Ctrl+C in backend window)
# Stop frontend (Ctrl+C in frontend window)
# Stop Docker
docker-compose down
```

---

## 📞 Support

If you encounter issues:
1. Check logs in each terminal
2. Ensure all prerequisites are installed
3. Verify ports are not in use
4. Restart Docker if needed
5. Run as Administrator for sensor

---

**Ready to launch? Follow the "Quick Start" section above!** 🚀
