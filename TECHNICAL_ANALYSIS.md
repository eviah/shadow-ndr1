# 🔬 Technical Analysis - Sensor Packet Capture Issue

## Problem Definition

```
Condition: cap.next_packet() returns timeout EVERY time
Effect:    No packets are processed
Duration:  Persistent across different interface types
```

## Root Cause Analysis

### The pcap Crate on Windows

The `pcap` crate (https://docs.rs/pcap/1.2.0/) is a Rust wrapper around:
- **libpcap** (Unix/Linux)  
- **Npcap** (Windows)
- **WinPcap** (older Windows, deprecated)

### Why This Fails

```
Sensor Code:
  let cap = Capture::from_device(dev)
    .promisc(true)
    .snaplen(65535)
    .timeout(1000)
    .immediate_mode(true)  ← PROBLEM on Windows!
    .open()?;
  
  cap.next_packet()  ← Always returns Timeout
```

**Why immediate_mode(true) causes problems:**

1. `immediate_mode()` is a Berkeley API feature
2. Npcap implements it, but with issues on some Windows versions
3. The pcap crate might use older Npcap SDK
4. Result: Packets queue in driver but never reach userland

---

## Solutions Applied

### ✅ Solution 1: Reduce Timeout (100ms)

```rust
// OLD
.timeout(1000)  // Wait 1 second for each packet

// NEW  
.timeout(100)   // Poll every 100ms
```

**Why This Helps:**
- Faster detection of real vs false timeouts
- More responsive polling
- Reduces blocked thread time

### ✅ Solution 2: Remove immediate_mode()

```rust
// REMOVED
.immediate_mode(true)

// Keep everything else - it works
```

**Why immediate_mode() is problematic:**
- Not fully compatible with all Npcap versions
- Can cause packets to hang in kernel buffer
- Works in Wireshark (different codebase) but not our pcap crate

### ✅ Solution 3: Better Error Handling

```rust
match cap.next_packet() {
    Ok(pkt) => { /* process */ },
    Err(e) => {
        let err_str = e.to_string();
        // Check if TIMEOUT or EAGAIN (both normal)
        if err_str.contains("timeout") || 
           err_str.contains("EAGAIN") || 
           err_str.contains("Timeout") {
            // Normal - no packets available
            continue;
        } else {
            // Real error - log and stop
            error!("Capture error: {}", e);
            break;
        }
    }
}
```

### ✅ Solution 4: Diagnostic Tool

```bash
cargo run --bin pcap_diag
```

Tests the full pcap stack:
1. Device enumeration
2. Device.open() 
3. next_packet() call
4. Reports exact failure point

---

## Still Doesn't Work? Next Steps

### Hypothesis 1: Npcap Driver Issue

**Test**: Use diagnostic tool
```
If: Successfully opened interface ✅ AND Got timeout ℹ️
Then: Driver is accepting connections but not forwarding packets
Fix: Reinstall Npcap with WinPcap-compatible mode
```

### Hypothesis 2: Windows Network Stack Issue

**Test**: Check if other capture tools work
```
If: Wireshark works but pcap_diag fails
Then: Windows Firewall or network settings blocking pcap
Fix: 
  netsh int ip set interface forwarding=enabled
  Check Windows Firewall exceptions
```

### Hypothesis 3: Wi-Fi Driver Incompatibility

**Test**: Try Ethernet interface
```
If: pcap_diag fails on Wi-Fi but could try Ethernet
Then: Wi-Fi driver doesn't support packet capture via pcap
Fix: Use Ethernet/Docked connection
```

### Hypothesis 4: pcap Crate Limitation

**Test**: Compare with system tools
```
If: All above work, but sensor still gets 0 packets
Then: pcap crate version or Npcap interaction issue
Fix: 
  - Update pcap crate (currently: 1.2)
  - OR switch to npcap-sys direct bindings
  - OR implement Windows native packet capture (WinDivert)
```

---

## Architecture of Packet Capture

```
┌─────────────────────────────────────────────────────┐
│             Physical Network                        │
└──────────────────┬──────────────────────────────────┘
                   │ Frames arrive
                   ▼
┌─────────────────────────────────────────────────────┐
│         Npcap Driver (Kernel Level)                 │
│  npcap.sys - captures frames from NIC              │
│  Filter: TCP/UDP/ICMP/etc                          │
└──────────────────┬──────────────────────────────────┘
                   │ Filtered frames queued
                   ▼
┌─────────────────────────────────────────────────────┐
│      Npcap API (wpcap.dll)                          │
│  pcap_open_live() ← opens handle                    │
│  pcap_next_packet() ← reads from queue              │
└──────────────────┬──────────────────────────────────┘
                   │
                   ▼
┌─────────────────────────────────────────────────────┐
│      pcap Crate (Rust Wrapper)                      │
│  Capture::from_device()                            │
│  cap.next_packet() ← STUCK HERE (timeout)          │
└──────────────────┬──────────────────────────────────┘
                   │
                   ▼
┌─────────────────────────────────────────────────────┐
│      Sensor Main Loop                              │
│  Process packets → Batch → Send to Backend         │
└─────────────────────────────────────────────────────┘
```

**Problem is likely at**: Npcap API ↔ pcap Crate interface

---

## Files Changed

### src/capture.rs
- Line 113: Changed timeout from 1000 to 100
- Line 114-115: Removed `.immediate_mode(true)`
- Line 157+: New error classification with logging

### src/config.rs  
- Line 45: Changed `bpf_filter: String` to `Option<String>`
- Line 88: Default to `bpf_filter: None`

### src/bin/pcap_diag.rs
- NEW FILE: Diagnostic utility
- Tests each component of the pcap stack separately

---

## Performance Notes

With changes:
- **Throughput**: Unchanged (if packets flow)
- **Latency**: Better (100ms timeout vs 1000ms)
- **CPU**: Same (polling interval doesn't change much)
- **Memory**: Unchanged

---

## Next Generation Solution (Future)

If pcap crate remains problematic, consider:

1. **WinDivert** - Direct userland packet diversion
   ```rust
   use windivert::*;
   let handle = WinDivert::new("true", WINDIVERT_LAYER::NETWORK, 0, 0)?;
   ```

2. **Actual npcap-sys** - Low-level bindings
   ```rust
   use npcap_sys::*;
   let pcap = pcap_open_live(...);
   ```

3. **Run on WSL2** - Use native Linux pcap
   ```bash
   # In WSL2
   sudo apt install libpcap-dev
   # Use Linux sensor
   ```

---

## Verification

When capture starts working, you'll see:

```json
{
  "timestamp": "2026-04-08T12:00:00Z",
  "level": "DEBUG",
  "message": "✅ Captured packet on Ethernet - 64 bytes"
}
```

Then metrics will show:
```
shadow_packets_processed_total 150
shadow_packets_sent_total 150
shadow_parse_errors_total 0
```

And backend will report:
```
POST /api/sensor/data 200 OK
```

---

**Technical Summary**: 
The issue is compatibility between the pcap Rust crate (1.2.0) and Npcap on Windows. Reducing timeout, removing immediate_mode, and adding better error handling should help. If not, the Npcap installation itself needs to be corrected or the approach needs to switch to native Windows packet capture APIs.

---

Date: April 8, 2026
Revised from initial analysis
