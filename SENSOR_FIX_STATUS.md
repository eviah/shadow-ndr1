# Shadow NDR Sensor - BPF Filter Fix

## Status: ✅ Code Changes Applied (Build in Progress)

### Changes Made

The sensor binary required a mandatory `--bpf-filter` parameter that should be optional. This has been fixed in the source code:

#### 1. **src/config.rs** - Made `bpf_filter` optional
```rust
// BEFORE
#[arg(long)]
pub bpf_filter: String,

// AFTER  
#[arg(long)]
pub bpf_filter: Option<String>,
```

Also updated in `AppConfig` struct and `Default` impl to use `Option<String>` and default to `None`.

#### 2. **src/capture.rs** - Updated BPF filter handling
```rust
// BEFORE
if !bpf_filter.is_empty() {
    cap.filter(&bpf_filter, true)?;
}

// AFTER
if let Some(ref filter) = bpf_filter {
    if !filter.is_empty() {
        cap.filter(filter, true)?;
    }
}
```

### Current Status

A `cargo build --release` is currently in progress to compile the sensor with these changes.

### How to Run Once Build Completes

After the build finishes, you can run the sensor WITHOUT requiring the `--bpf-filter` parameter:

```powershell
# Option 1: Run with no parameters (uses empty filter - captures all)
.\target\release\shadow-sensor.exe

# Option 2: Run with custom BPF filter
.\target\release\shadow-sensor.exe --bpf-filter "ip"

# Option 3: Run with specific interface
.\target\release\shadow-sensor.exe --interfaces "\Device\NPF_{YOUR_GUID}"
```

### Expected Startup Output

Once the binary is built and running, you should see:

```
🚀 Starting Shadow NDR Ultimate Sensor v5.0.0
✅ Configuration loaded
📊 Metrics endpoint: http://0.0.0.0:9090/metrics
💚 Health endpoint: http://0.0.0.0:8081/health
✅ Capture engine running on 1 interface(s)
```

### Testing the Sensor

Once running, test in another PowerShell window:

```powershell
# Check health
curl http://localhost:8081/health

# Check metrics
curl http://localhost:9090/metrics
```

### Build Details

- **Build Command**: `cargo build --release`
- **Location**: `C:\Users\liorh\shadow-ndr\shadow-sensor`
- **Binary Output**: `target\release\shadow-sensor.exe`
- **Estimated Build Time**: 3-5 minutes

---

**Status Last Updated**: 2026-04-06 18:40 UTC
