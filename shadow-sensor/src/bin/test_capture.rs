use pcap::Device;

fn main() {
    println!("Testing pcap capture...\n");
    
    // מצא את ממשק ה-WiFi
    let devices = Device::list().unwrap();
    
    println!("Available devices:");
    for dev in &devices {
        println!("  - {}", dev.name);
        if let Some(desc) = &dev.desc {
            println!("    Description: {}", desc);
        }
    }
    
    println!("\nSearching for Wi-Fi interface...");
    let wifi = devices.iter().find(|d| {
        d.desc.as_ref().map_or(false, |desc| desc.contains("Wi-Fi") || desc.contains("WiFi"))
    }).expect("Wi-Fi interface not found");
    
    println!("\n✅ Found Wi-Fi interface:");
    println!("  Name: {}", wifi.name);
    println!("  Description: {:?}", wifi.desc);
    
    println!("\nOpening capture on Wi-Fi interface...");
    let mut cap = wifi.clone().open().expect("Failed to open interface");
    
    println!("✅ Successfully opened!\n");
    println!("Attempting to capture 10 packets (waiting up to 5 seconds)...\n");
    
    let mut count = 0;
    for i in 1..=10 {
        match cap.next_packet() {
            Ok(pkt) => {
                println!("✅ Packet {}: {} bytes", i, pkt.len());
                count += 1;
            }
            Err(e) => {
                let err_str = e.to_string();
                if err_str.contains("timeout") || err_str.contains("Timeout") {
                    println!("⏳ Packet {}: Timeout (no packet available)", i);
                } else {
                    println!("❌ Packet {}: Error: {}", i, e);
                }
            }
        }
    }
    
    println!("\n════════════════════════════════════════════");
    println!("Results: {} packets captured out of 10", count);
    
    if count > 0 {
        println!("✅ SUCCESS - Pcap is working!");
        println!("The sensor should be able to capture packets.");
    } else {
        println!("❌ FAILURE - No packets captured");
        println!("This means either:");
        println!("  1. No network traffic on this interface");
        println!("  2. Npcap driver issue (reinstall needed)");
        println!("  3. Windows Firewall blocking capture");
    }
    println!("════════════════════════════════════════════");
}
