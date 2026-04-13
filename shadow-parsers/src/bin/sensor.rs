//! Shadow NDR Aviation Sensor – Main Entry Point

use anyhow::{Context, Result};
use std::net::UdpSocket;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

// Import parsers
use shadow_parsers::adsb::parse_adsb;
use shadow_parsers::acars::parse_acars;
use shadow_parsers::mode_s::parse_mode_s;
use shadow_parsers::vdl::parse_vdl;
use shadow_parsers::cpdlc::parse_cpdlc;
use shadow_parsers::aeromacs::parse_aeromacs;
use shadow_parsers::iec104::parse_iec104;

// CLI parsing with clap
use clap::Parser;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Network interface to capture from (e.g., eth0, any)
    #[arg(short, long, default_value = "any")]
    interface: String,

    /// Kafka brokers (comma‑separated). If empty, no Kafka output.
    #[arg(short = 'b', long, default_value = "")]
    kafka_brokers: String,

    /// Kafka topic to send data to.
    #[arg(short = 't', long, default_value = "shadow.raw")]
    kafka_topic: String,

    /// BPF filter for packet capture (not used in UDP mode)
    #[arg(long, default_value = "")]
    bpf_filter: String,

    /// UDP port to listen on for incoming raw packets.
    #[arg(short, long, default_value = "9999")]
    udp_port: u16,
}

fn main() -> Result<()> {
    env_logger::init();
    let args = Args::parse();

    println!("Shadow NDR Aviation Sensor v{}", env!("CARGO_PKG_VERSION"));
    println!("Interface: {}", args.interface);
    println!("UDP port: {}", args.udp_port);
    if !args.kafka_brokers.is_empty() {
        println!("Kafka brokers: {}", args.kafka_brokers);
        println!("Kafka topic: {}", args.kafka_topic);
    } else {
        println!("Kafka output disabled (no brokers specified)");
    }

    // Set up a UDP socket to receive packets.
    let addr = format!("0.0.0.0:{}", args.udp_port);
    let socket = UdpSocket::bind(&addr)
        .with_context(|| format!("Failed to bind to UDP port {}", args.udp_port))?;
    println!("Listening for UDP packets on {}", addr);
    println!("Press Ctrl+C to stop");

    // Atomic flag for graceful shutdown.
    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();
    ctrlc::set_handler(move || {
        println!("\nShutdown signal received, stopping sensor...");
        r.store(false, Ordering::SeqCst);
    })
    .expect("Error setting Ctrl+C handler");

    let mut buf = [0u8; 65536];
    let mut packet_count = 0u64;

    while running.load(Ordering::SeqCst) {
        match socket.recv_from(&mut buf) {
            Ok((size, src)) => {
                packet_count += 1;
                let data = &buf[..size];

                // Try to parse as ADS-B first
                if let Ok(frame) = parse_adsb(data) {
                    println!("[{}] ADS-B: ICAO {:06X}, callsign: {:?}, emergency: {}",
                          packet_count, frame.icao24, frame.callsign, frame.emergency);
                }
                // Try ACARS
                else if let Ok(frame) = parse_acars(data) {
                    println!("[{}] ACARS: {} - {}", packet_count, frame.aircraft_id, frame.message_text);
                }
                // Try Mode S
                else if let Ok(frame) = parse_mode_s(data) {
                    println!("[{}] Mode S: ICAO {:06X}", packet_count, frame.icao24);
                }
                // Try VDL
                else if let Ok(frame) = parse_vdl(data) {
                    println!("[{}] VDL Mode 2: {} → {}", packet_count, frame.source, frame.destination);
                }
                // Try CPDLC
                else if let Ok(frame) = parse_cpdlc(data) {
                    println!("[{}] CPDLC: {} - {}", packet_count, frame.aircraft_id, frame.message);
                }
                // Try AeroMACS
                else if let Ok(frame) = parse_aeromacs(data) {
                    println!("[{}] AeroMACS: {} → {}", packet_count, 
                           hex::encode(&frame.source_mac), hex::encode(&frame.dest_mac));
                }
                // Try IEC104
                else if let Ok(frame) = parse_iec104(data) {
                    println!("[{}] IEC 104: APCI {:?}", packet_count, frame.apci);
                }
                else {
                    println!("[{}] Unknown packet: {} bytes from {}", packet_count, size, src);
                }
            }
            Err(e) => {
                eprintln!("Receive error: {}", e);
                thread::sleep(Duration::from_millis(100));
            }
        }
    }

    println!("Sensor stopped after processing {} packets.", packet_count);
    Ok(())
}