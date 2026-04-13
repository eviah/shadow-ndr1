# 🚀 Shadow NDR Sensor - Quick Start Guide

## ⚡ IMMEDIATE WORKAROUND (While Build Completes)

Until the full rebuild completes, you can run the sensor with this command:

```powershell
cd C:\Users\liorh\shadow-ndr\shadow-sensor
.\target\release\shadow-sensor.exe --bpf-filter ""
```

Or to capture only IP traffic:

```powershell
.\target\release\shadow-sensor.exe --bpf-filter "ip"
```

---

## 📋 Full Deployment Sequence

### Window 1: Backend (Node.js)
```powershell
cd C:\Users\liorh\shadow-ndr\multi-tenant\backend
npm install
npm run dev
```

Expected output:
```
✅ Server running on port 3001
✅ PostgreSQL connected
✅ Redis connected
```

### Window 2: Frontend (React)
```powershell
cd C:\Users\liorh\shadow-ndr\multi-tenant\frontend
npm install
npm run dev
```

Expected output:
```
✅ Local: http://localhost:3000
```

### Window 3: Sensor (Run as Administrator)
```powershell
cd C:\Users\liorh\shadow-ndr\shadow-sensor

# Option 1: Empty filter (capture all)
.\target\release\shadow-sensor.exe --bpf-filter ""

# Option 2: IP traffic only
.\target\release\shadow-sensor.exe --bpf-filter "ip"

# Option 3: Specific interface
.\target\release\shadow-sensor.exe --interfaces "\Device\NPF_{YOUR_GUID}" --bpf-filter "ip"
```

Expected output:
```
🚀 Starting Shadow NDR Ultimate Sensor v5.0.0
✅ Configuration loaded
📊 Metrics endpoint: http://0.0.0.0:9090/metrics
💚 Health endpoint: http://0.0.0.0:8081/health
✅ Capture engine running on 1 interface(s)
```

### Window 4: Testing (PowerShell)
```powershell
# Test sensor health
curl http://localhost:8081/health

# Test metrics
curl http://localhost:9090/metrics

# Test backend
curl http://localhost:3001/api/sensor/stats
```

---

## ✅ Verification Checklist

- [ ] Backend running on port 3001
- [ ] Frontend accessible on http://localhost:3000
- [ ] Sensor running (health endpoint responds)
- [ ] Metrics available on http://localhost:9090/metrics
- [ ] Backend receiving sensor data (`POST /api/sensor/data`)

---

## 🔧 If Sensor Still Won't Start

### Check Interface Availability
```powershell
# Run from sensor directory
.\target\release\shadow-sensor.exe --help
```

Look for `--interfaces` option usage.

### List Available Interfaces
```powershell
# Using PowerShell
[System.Net.NetworkInformation.NetworkInterface]::GetAllNetworkInterfaces() | 
  Select-Object Name, Description | Format-Table

# Or check Windows Network Settings
ipconfig /all
```

### Verify Npcap Installation
```powershell
# Check if Npcap is installed
Get-ChildItem 'C:\Windows\System32\Npcap\' -ErrorAction SilentlyContinue

# If missing, download from: https://npcap.com/dist/npcap-1.81.exe
```

---

## 🎯 Performance Optimization

### Increase Batch Size (for high traffic)
```powershell
.\target\release\shadow-sensor.exe --bpf-filter "ip" --batch-size 500
```

### Increase Rate Limit (packets per second)
```powershell
.\target\release\shadow-sensor.exe --bpf-filter "ip" --rate-limit-pps 200000
```

### Enable Compression
```powershell
.\target\release\shadow-sensor.exe --bpf-filter "ip" --compression-enabled true
```

---

## 📊 Expected Metrics

Once running, check these metrics:

```powershell
# Get all metrics
curl http://localhost:9090/metrics | Select-String "shadow_" -Context 0,1
```

Key metrics to monitor:
- `shadow_packets_processed_total` - Total packets processed
- `shadow_packets_sent_total` - Successfully sent to backend
- `shadow_parse_errors_total` - Failed to parse packets
- `shadow_send_errors_total` - Failed to send to backend

---

## 🐛 Troubleshooting

| Issue | Solution |
|-------|----------|
| `wpcap.lib not found` | Install Npcap with "WinPcap API-compatible Mode" |
| `No interfaces found` | Run as Administrator; check Npcap installation |
| `Connection refused` | Ensure backend is running on port 3001 |
| `All packets fail to send` | Check backend is accepting `/api/sensor/data` POST requests |
| `Health endpoint not responding` | Sensor process may have crashed; check terminal output |

---

**Next Step**: Once the build completes, the sensor will run without requiring `--bpf-filter` argument!
