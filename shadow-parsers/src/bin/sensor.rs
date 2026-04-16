//! Shadow NDR Aviation Sensor – Project Titan Architecture
//!
//! Features:
//! - Tokio async runtime for non-blocking I/O
//! - LMAX-like disruptor pattern using crossbeam-channel
//! - Real-time Kinematic Physics validation
//! - Zero-blocking asynchronous Kafka delivery via rdkafka

use anyhow::{Context, Result};
use clap::Parser;
use crossbeam_channel::{bounded, Receiver, Sender};
use log::{error, info, warn};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::net::UdpSocket;

// Internal Modules
use shadow_parsers::adsb::{parse_adsb, AdsbMessage};
use shadow_parsers::acars::parse_acars;
use shadow_parsers::kafka::{KafkaDispatcher, KafkaMessage};
use shadow_parsers::physics::{KinematicEngine, PhysicalState};

// =============================================================================
// CLI Configuration
// =============================================================================

#[derive(Parser, Debug, Clone)]
#[command(author, version, about = "Shadow NDR - Aviation Protocol Engine")]
struct Args {
    /// UDP port to listen on for raw packets
    #[arg(short, long, default_value = "9999")]
    udp_port: u16,

    /// Kafka brokers (comma‑separated).
    #[arg(short = 'b', long, default_value = "localhost:9092")]
    kafka_brokers: String,

    /// Kafka topic for raw frames
    #[arg(short = 'r', long, default_value = "shadow.raw")]
    raw_topic: String,

    /// Kafka topic for physics & threat alerts
    #[arg(short = 't', long, default_value = "shadow.threats")]
    threat_topic: String,

    /// Number of worker threads for parallel parsing
    #[arg(short = 'w', long, default_value = "4")]
    workers: usize,
}

// =============================================================================
// Engine State & Enums
// =============================================================================

/// A raw packet ingested from the socket
struct RawPacket {
    data: Vec<u8>,
    timestamp_ms: u64,
}

// =============================================================================
// Core Pipeline
// =============================================================================

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();
    let args = Args::parse();
    info!("Starting Shadow NDR Aviation Sensor v{}", shadow_parsers::VERSION);

    // 1. Initialize Kafka Dispatcher
    let dispatcher = KafkaDispatcher::new(&args.kafka_brokers, &args.raw_topic, &args.threat_topic)?;
    let kafka_tx = dispatcher.spawn_dispatcher();

    // 2. Setup Disruptor Pattern (Crossbeam Channels)
    // - Ingress channel: NIC -> Workers (bounded to prevent OOM)
    // - Physics channel: Workers -> Physics Engine
    let (ingress_tx, ingress_rx) = bounded::<RawPacket>(500_000);
    let (physics_tx, physics_rx) = bounded::<PhysicalState>(100_000);

    // 3. Spawn Physics / Stateful Firewall Thread
    spawn_physics_engine(physics_rx, kafka_tx.clone());

    // 4. Spawn Parsing Workers
    for i in 0..args.workers {
        spawn_worker(i, ingress_rx.clone(), physics_tx.clone(), kafka_tx.clone());
    }

    // 5. Ingress Layer (Network Capture)
    let addr = format!("0.0.0.0:{}", args.udp_port);
    let socket = UdpSocket::bind(&addr).await.context("Failed to bind UDP")?;
    info!("Listening for high-throughput UDP packets on {}", addr);

    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();
    ctrlc::set_handler(move || {
        warn!("Graceful shutdown requested...");
        r.store(false, Ordering::SeqCst);
    }).expect("Failed to set Ctrl+C handler");

    // Ingest loop: highly optimized tight loop
    let mut buf = vec![0u8; 65536];
    while running.load(Ordering::SeqCst) {
        if let Ok((size, _src)) = socket.try_recv_from(&mut buf) {
            let msg = RawPacket {
                data: buf[..size].to_vec(),
                timestamp_ms: SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_millis() as u64,
            };

            // Non-blocking push to workers
            if let Err(_) = ingress_tx.try_send(msg) {
                // If channel full, drop packet (sensor overloaded)
                // In production, increment drop metric here
            }
        } else {
            tokio::task::yield_now().await;
        }
    }

    info!("Sensor shutting down.");
    drop(ingress_tx);
    drop(physics_tx);
    // Give tasks a second to flush
    tokio::time::sleep(tokio::time::Duration::from_millis(1500)).await;

    Ok(())
}

// =============================================================================
// Threads
// =============================================================================

fn spawn_worker(
    id: usize,
    rx: Receiver<RawPacket>,
    physics_tx: Sender<PhysicalState>,
    kafka_tx: tokio::sync::mpsc::Sender<KafkaMessage>,
) {
    std::thread::spawn(move || {
        info!("Worker {} ready.", id);
        while let Ok(packet) = rx.recv() {
            // 1. Try ADS-B
            if let Ok(frame) = parse_adsb(&packet.data) {
                // JSON serialize and send to Kafka
                if let Ok(json) = serde_json::to_string(&frame) {
                    let _ = kafka_tx.try_send(KafkaMessage::ParsedFrame(json));
                }

                // If it contains physical state, send to Physics Engine
                match frame.message {
                    AdsbMessage::AirbornePosition(pos) => {
                        // In reality, this requires CPR decoding which involves last Even/Odd frames.
                        // Here we simulate the parsed Lat/Lon for the physics engine API.
                        let state = PhysicalState {
                            icao24: frame.icao24,
                            lat: (pos.cpr_encoded_lat as f64) * 0.001, // Mock CPR unpack
                            lon: (pos.cpr_encoded_lon as f64) * 0.001,
                            altitude_ft: pos.altitude as i32,
                            velocity_knots: None,
                            heading: None,
                            timestamp_ms: packet.timestamp_ms,
                        };
                        let _ = physics_tx.try_send(state);
                    }
                    AdsbMessage::AirborneVelocity(vel) => {
                        let state = PhysicalState {
                            icao24: frame.icao24,
                            lat: 0.0,
                            lon: 0.0, // Should be cached/joined from previous
                            altitude_ft: 0,
                            velocity_knots: Some(vel.velocity_knots),
                            heading: Some(vel.heading_degrees),
                            timestamp_ms: packet.timestamp_ms,
                        };
                        let _ = physics_tx.try_send(state);
                    }
                    _ => {}
                }
                continue;
            }

            // 2. Try ACARS
            if let Ok(frame) = parse_acars(&packet.data) {
                if let Ok(json) = serde_json::to_string(&frame) {
                    let _ = kafka_tx.try_send(KafkaMessage::ParsedFrame(json));
                }
                continue;
            }
        }
    });
}

fn spawn_physics_engine(
    rx: Receiver<PhysicalState>,
    kafka_tx: tokio::sync::mpsc::Sender<KafkaMessage>,
) {
    std::thread::spawn(move || {
        info!("Kinematic Physics Validation Engine active.");
        let mut engine = KinematicEngine::new();

        while let Ok(state) = rx.recv() {
            if let Some(anomaly) = engine.process_state(state.clone()) {
                // Formatting anomaly alert
                let alert = serde_json::json!({
                    "icao24": state.icao24,
                    "anomaly_type": format!("{:?}", anomaly),
                    "timestamp_ms": state.timestamp_ms,
                    "severity": "CRITICAL"
                });
                
                let _ = kafka_tx.try_send(KafkaMessage::ThreatAlert(alert.to_string()));
            }
        }
    });
}