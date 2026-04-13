/// Diagnostic tool for pcap/Npcap issues
/// Run as Administrator: cargo run --bin pcap_diag --release

use std::time::Duration;

fn main() {
    println!("🔍 PCAP Diagnostic Tool for Shadow NDR Sensor\n");
    println!("═══════════════════════════════════════════════════════════\n");

    // Step 1: List devices
    println!("Step 1: Listing available pcap devices...\n");
    let devices = match pcap::Device::list() {
        Ok(devs) => devs,
        Err(e) => {
            println!("❌ FAILED to list devices: {}\n", e);
            println!("This means:");
            println!("  - Npcap is not installed, OR");
            println!("  - wpcap.dll is not in PATH, OR");
            println!("  - There's a compatibility issue\n");
            println!("Solution: Install Npcap from https://npcap.com/");
            return;
        }
    };

    if devices.is_empty() {
        println!("❌ No devices found!\n");
        println!("This means:");
        println!("  - Npcap is installed but no network interfaces are visible\n");
        return;
    }

    println!("✅ Found {} device(s):\n", devices.len());
    for (i, dev) in devices.iter().enumerate() {
        println!("  {}. Name: {}", i + 1, dev.name);
        println!("     Desc: {:?}", dev.desc);
        println!("     Addrs: {:?}\n", dev.addresses);
    }

    // Step 2: Try to open each interface
    println!("\nStep 2: Attempting to open each interface...\n");
    
    for dev in &devices {
        println!("Testing interface: {}", dev.name);
        println!("  Description: {:?}", dev.desc);

        match pcap::Capture::from_device(dev.clone()) {
            Ok(cap_builder) => {
                println!("  ✅ Can create capture builder");
                
                // Try to open it
                match cap_builder
                    .promisc(true)
                    .snaplen(65535)
                    .timeout(100)
                    .open()
                {
                    Ok(mut cap) => {
                        println!("  ✅ Successfully opened for capture");
                        
                        // Try to read one packet with timeout
                        println!("  ⏳ Attempting to read a packet (waiting 500ms)...");
                        std::thread::sleep(Duration::from_millis(500));
                        
                        match cap.next_packet() {
                            Ok(packet) => {
                                println!("  ✅ Successfully read a packet!");
                                println!("     Packet size: {} bytes", packet.data.len());
                            }
                            Err(e) => {
                                let err_str = e.to_string();
                                if err_str.contains("timeout") || err_str.contains("EAGAIN") || err_str.contains("Timeout") {
                                    println!("  ℹ️  Got timeout (normal if no traffic): {}", e);
                                } else {
                                    println!("  ❌ Error reading packet: {}", e);
                                }
                            }
                        }
                    }
                    Err(e) => {
                        println!("  ❌ Failed to open: {}", e);
                        println!("     Possible causes:");
                        println!("     - Interface is busy (Wireshark using it?)");
                        println!("     - Insufficient permissions (not admin?)");
                        println!("     - Npcap driver issue");
                    }
                }
            }
            Err(e) => {
                println!("  ❌ Cannot create builder: {}", e);
            }
        }
    }

    // Step 3: Final recommendations
    println!("\n═══════════════════════════════════════════════════════════");
    println!("\n🎯 RECOMMENDATIONS:\n");
    
    if devices.is_empty() {
        println!("❌ No interfaces found - Npcap driver issue");
        println!("   → Reinstall Npcap: https://npcap.com/dist/npcap-1.81.exe");
        println!("   → Enable: WinPcap API-compatible Mode");
        println!("   → Enable: Support raw 802.11 traffic");
        println!("   → Disable: Restrict driver to Administrators\n");
    } else {
        println!("✅ Basic infrastructure is working");
        println!("   → If sensor still doesn't capture packets:");
        println!("   → Try switching to Ethernet instead of Wi-Fi");
        println!("   → Try disconnecting Wireshark/other capture tools");
        println!("   → Check Windows Firewall - might be blocking");
        println!("   → Run: netsh int ip set int interface=<name> forwarding=enabled\n");
    }

    println!("═══════════════════════════════════════════════════════════\n");
}
