# 🚀 Shadow NDR Sensor - Troubleshooting Packet Capture Issue

## ✅ **BUILD COMPLETE** - Sensor Binary Ready!

📍 **Binary Location**: `C:\Users\liorh\shadow-ndr\shadow-sensor\target\release\shadow-sensor.exe` (6.3 MB)

---

## 🎯 **Your Situation**

**Problem**: The sensor is running but **NOT capturing any packets**
- Npcap is installed ✅
- Wireshark can capture on the same interface ✅
- Sensor starts without errors ✅
- But sensor receives **0 packets** ❌

**Root Cause**: The `pcap` crate (Rust library) isn't properly receiving packets from Npcap driver on Windows

---

## 📋 **IMMEDIATE ACTION PLAN**

### **1️⃣ Run Diagnostic Tool** (Do THIS first!)

```powershell
# Open PowerShell as Administrator
cd C:\Users\liorh\shadow-ndr\shadow-sensor

# Build the diagnostic tool
cargo build --release --bin pcap_diag 2>&1 | Select-String "Finished"

# Run it
.\target\release\pcap_diag.exe
```

**What to look for in output:**
- ✅ "Successfully opened for capture" on your interface → Good, hardware OK
- ℹ️ "Got timeout" → Normal if no traffic
- ❌ "Error reading packet" (non-timeout) → Npcap/driver issue

**If diagnostic works** but sensor still doesn't capture:
→ Problem is in our capture loop, not Npcap

**If diagnostic FAILS**:
→ Npcap installation or Windows system issue

---

### **2️⃣ Test Sensor with Enabled Logging**

```powershell
# Set debug logging
$env:RUST_LOG = "debug"

# Run sensor
.\target\release\shadow-sensor.exe --bpf-filter ""

# Watch the logs for:
# ✅ "Successfully opened interface: ..."
# ✅ "Capture engine running on X interface(s)"
# ✅ "Captured packet on eth0 - XXX bytes" ← If you see this, PACKETS ARE BEING CAPTURED!
# ❌ "Timeouts on eth0: X consecutive (no packets yet)" ← If only this, NO PACKETS
```

---

### **3️⃣ Based on Results...**

#### **Case A: Sensor IS capturing packets (you see "Captured packet")**

Great! The problem was just configuration. Next:

```powershell
# Stop sensor (Ctrl+C)

# Start everything together:
# Window 1: Backend
cd C:\Users\liorh\shadow-ndr\multi-tenant\backend
npm run dev

# Window 2: Frontend  
cd C:\Users\liorh\shadow-ndr\multi-tenant\frontend
npm run dev

# Window 3: Sensor (Admin)
cd C:\Users\liorh\shadow-ndr\shadow-sensor
.\target\release\shadow-sensor.exe --bpf-filter ""

# Window 4: Test
curl http://localhost:8081/health
curl http://localhost:3000
```

---

#### **Case B: Sensor NOT capturing (only "Timeouts")**

The pcap crate can't get packets from Npcap. Try these fixes:

##### **Fix #1: Reinstall Npcap Correctly** ⭐ MOST LIKELY TO WORK

```powershell
# 1. Uninstall current Npcap
#    Settings → Apps → Installed apps → Search "Npcap" → Uninstall

# 2. Restart Windows

# 3. Download fresh: https://npcap.com/dist/npcap-1.81.exe

# 4. Run installer WITH THESE SETTINGS:
#    ✅ WinPcap API-compatible Mode (MUST CHECK)
#    ❌ DON'T check "Restrict driver to Administrators"
#    ✅ Support raw 802.11 traffic (if Wi-Fi)
#    ✅ NDIS 6.0 support (if available)

# 5. Reboot

# 6. Test again:
.\target\release\pcap_diag.exe
```

##### **Fix #2: Try Ethernet Instead of Wi-Fi**

Wi-Fi capture sometimes has compatibility issues:

```powershell
# If you have USB Ethernet dongle or docked connection
.\target\release\shadow-sensor.exe --bpf-filter "" --interfaces "Ethernet"
```

##### **Fix #3: Enable Windows Network Forwarding**

```powershell
# Run as Administrator
netsh interface ipv4 set interface "Wi-Fi" forwarding=enabled
# OR for Ethernet:
netsh interface ipv4 set interface "Ethernet" forwarding=enabled
```

Then test sensor again.

##### **Fix #4: Use Raw Sockets (Last Resort)**

There's an alternative backend we can implement using Windows native APIs. For now:

```powershell
# Try with very short timeout
.\target\release\shadow-sensor.exe --bpf-filter "" --batch-flush-interval-ms 50
```

---

## 🔧 **Code Changes Made (Summary)**

1. **capture.rs**
   - Reduced timeout from 1000ms → 100ms (more responsive)
   - Removed `immediate_mode(true)` (Windows incompatibility)
   - Better timeout vs error handling
   - Enhanced logging for debugging

2. **config.rs**
   - Made `--bpf-filter` optional (was required)
   - Default: `None` (capture everything)

3. **bin/pcap_diag.rs** (NEW)
   - Standalone diagnostic tool
   - Tests each interface independently
   - Shows exact error messages

---

## 📊 **What We Know**

| Component | Status |
|-----------|--------|
| Npcap installed | ✅ Yes |
| wpcap.dll found | ✅ Yes  |
| Wireshark captures | ✅ Yes |
| Sensor starts | ✅ Yes |
| **Sensor captures** | ❌ **NO** |
| Backend API | ✅ Working |
| Frontend | ✅ Working |

---

## 🎯 **Success Criteria**

Your problem is **SOLVED** when you see in sensor logs:

```
✅ Captured packet on Ethernet - 64 bytes
✅ Captured packet on Ethernet - 1500 bytes
Batch: len=100, parsed=95, ok=95, fail=0 in 125ms
```

---

## 📞 **If Still Stuck**

Run diagnostic and share its output:

```powershell
.\target\release\pcap_diag.exe | Tee-Object diag_output.txt
```

Then the exact error messages from:

```powershell
$env:RUST_LOG = "debug"
.\target\release\shadow-sensor.exe --bpf-filter "" 2>&1 | Select-Object -First 100 | Tee-Object sensor_log.txt
```

---

## 🚀 **Quick Start (Once Working)**

```powershell
# Terminal 1 - Backend
cd C:\Users\liorh\shadow-ndr\multi-tenant\backend
npm run dev

# Terminal 2 - Frontend
cd C:\Users\liorh\shadow-ndr\multi-tenant\frontend
npm run dev

# Terminal 3 - Sensor (ADMIN)
cd C:\Users\liorh\shadow-ndr\shadow-sensor
.\target\release\shadow-sensor.exe --bpf-filter ""

# Terminal 4 - Test
curl http://localhost:3000  # Frontend
curl http://localhost:3001/api/stats  # Backend
curl http://localhost:8081/health  # Sensor health
curl http://localhost:9090/metrics | Select-String "shadow_packets"
```

---

**Next Step**: Run the diagnostic tool and check if packets are being captured! 🎯

---

Date: April 8, 2026
Version: Shadow NDR v5.0.0
