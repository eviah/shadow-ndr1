use pcap::Device;

fn main() {
    match Device::list() {
        Ok(devices) => {
            println!("Found {} devices:", devices.len());
            for (i, dev) in devices.iter().enumerate() {
                println!("  {}: {} - {:?}", i, dev.name, dev.desc);
            }
        }
        Err(e) => println!("Error listing devices: {}", e),
    }
}
