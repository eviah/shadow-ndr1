# 🔧 Shadow NDR Sensor - Packet Capture Fix Guide

## 🎯 Problem Summary

The sensor successfully connects to network interfaces but **never receives any packets** - even when Wireshark captures them on the same interface. All `cap.next_packet()` calls return "timeout expired" errors.

**Root Cause**: The pcap Rust crate may have compatibility issues with Npcap on Windows, or the capture session isn't properly configured.

---

## ✅ Changes Applied

### 1. **Capture Timeout Optimization** (capture.rs)
- **Old**: `timeout(1000)` - 1 second timeout per packet
- **New**: `timeout(100)` - 100ms timeout for more responsive polling
- **Removed**: `immediate_mode(true)` - caused issues on Windows
- **Improved**: Better error handling for timeouts vs real errors

### 2. **Enhanced Logging**
- Added debug logging for successful packet capture
- Added detailed timeout tracking to detect prolonged failures
- Better error classification

### 3. **Diagnostic Tool** (pcap_diag binary)
Created a standalone diagnostic tool to test pcap functionality:

```bash
cargo run --bin pcap_diag --release
```

This tool:
- Lists all available network interfaces
- Attempts to open each one
- Tries to read a packet from each
- Reports success/failure for troubleshooting

---

## 📋 Debugging Steps

### **Step 1: Run the Diagnostic Tool** (FIRST!)

```powershell
cd C:\Users\liorh\shadow-ndr\shadow-sensor
cargo build --release --bin pcap_diag
.\target\release\shadow-sensor.exe --help  # Just to see if it runs

# Actually run the diagnostic
.\target\release\pcap_diag.exe
```

Expected output with the diagnostic tool will tell you:
- ✅ If Npcap is working at all
- ✅ Which interfaces can be opened
- ℹ️ If timeouts are normal or if there's a deeper issue

### **Step 2: Test with Simple Filter**

Run the sensor with minimal configuration:

```powershell
# No BPF filter - capture everything
cd C:\Users\liorh\shadow-ndr\shadow-sensor
.\target\release\shadow-sensor.exe --bpf-filter ""
```

Watch the logs:
- If you see `✅ Captured packet on eth0 - XXX bytes`, packets ARE being captured
- If you only see timeouts, packets are NOT being captured

### **Step 3: Verify with Wireshark**

While the sensor is running:

```powershell
# In another window, check if the sensor is even trying
Get-Process | Select-String "shadow-sensor|wireshark"
```

If Wireshark can capture but sensor can't on the SAME interface, the issue is in the pcap crate or Npcap configuration.

---

##  🚨 If Still No Packets Captured

### **Option 1: Reinstall Npcap with Correct Settings**

1. **Uninstall** current Npcap:
   - Control Panel → Programs → Uninstall
   - Select "Npcap" and remove

2. **Download Fresh**: https://npcap.com/dist/npcap-1.81.exe

3. **Install with THESE exact settings**:
   - ✅ **WinPcap API-compatible Mode** (CRITICAL)
   - ❌ **DON'T** check "Restrict driver to Administrators"
   - ✅ **Support raw 802.11 traffic** 
   - ✅ **NDIS 6.0 driver** (check if available)
   - ✅ **DLL only** (if separate option)

4. **Reboot** your computer

5. **Run diagnostic again**:
   ```powershell
   .\target\release\pcap_diag.exe
   ```

### **Option 2: Switch to Ethernet Instead of Wi-Fi**

Some systems have issues with Wi-Fi capture. If you have:
- USB Ethernet dongle
- Docking station with RJ45
- Direct ethernet connection

Try capturing on that interface instead:

```powershell
# List interfaces
.\target\release\pcap_diag.exe

# Run on specific interface (get name from diagnostic output)
.\target\release\shadow-sensor.exe --interfaces "Local Area Connection" --bpf-filter ""
```

### **Option 3: Windows Firewall / Network Settings**

Try these commands in PowerShell (as Administrator):

```powershell
# Enable IP forwarding on the interface (replace "Ethernet" with your interface name)
netsh interface ipv4 set interface "Ethernet" forwarding=enabled

# Or for Wi-Fi:
netsh interface ipv4 set interface "Wi-Fi" forwarding=enabled

# Check promiscuous mode
netsh interface ip show interfaces
```

### **Option 4: Use tcpdump Alternative** (Linux-style)

If you have WSL2 (Windows Subsystem for Linux), you could try capturing from Linux, but this is complex.

---

## 💻 Running the Sensor (Current Status)

Once the build completes:

### **Standard Run** (Admin PowerShell):
```powershell
cd C:\Users\liorh\shadow-ndr\shadow-sensor
.\target\release\shadow-sensor.exe --bpf-filter ""
```

### **With Specific Interface**:
```powershell
# First, get the interface name from pcap_diag
.\target\release\pcap_diag.exe

# Then run with that interface:
.\target\release\shadow-sensor.exe --interfaces "\Device\NPF_{GUID}" --bpf-filter ""
```

### **With Debugging Enabled**:
```powershell
$env:RUST_LOG="debug"
.\target\release\shadow-sensor.exe --bpf-filter ""
```

---

## 🎯 Success Indicators

When the sensor IS working, you should see in the logs:

```
🚀 Starting Shadow NDR Ultimate Sensor v5.0.0
✅ Configuration loaded
✅ Successfully opened interface: {Ethernet name}
✅ Capture engine running on 1 interface(s)
✅ Captured packet on {interface} - XXX bytes
Batch: len=50, parsed=45, ok=45, fail=0 in 25ms
```

When NOT working, you see:

```
Timeouts on {interface}: 50 consecutive (no packets yet)
```

---

## 📊 Architecture Info

The sensor captures traffic in stages:

1. **Open Interface** → Uses `Capture::from_device()` + pcap crate
2. **Read Packets** → Uses `cap.next_packet()` in a loop
3. **Buffer** → Batches packets via `crossbeam_channel`
4. **Process** → Parses 20+ protocols (async with Rayon)
5. **Send** → Posts to backend at `/api/sensor/data`

The **problem is at stage 2** - `next_packet()` never returns data.

---

## 🔗 Related Files Modified

- `src/capture.rs` - Improved packet capture loop
- `src/config.rs` - Made bpf_filter optional
- `src/bin/pcap_diag.rs` - NEW diagnostic tool
- `src/main.rs` - No changes
- `Cargo.toml` - No changes

---

##  **Next Steps**

1. **Wait for build to complete** (currently compiling)
2. **Run diagnostic tool** to understand the issue
3. **Follow debugging steps above** based on diagnostic output
4. **Share diagnostic output** if you need help

---

**Status**: Build in progress. Once complete, sensor binary will be at:
```
C:\Users\liorh\shadow-ndr\shadow-sensor\target\release\shadow-sensor.exe
```

Diagnostic tool will be at:
```
C:\Users\liorh\shadow-ndr\shadow-sensor\target\release\pcap_diag.exe
```

---

**Last Updated**: April 8, 2026
