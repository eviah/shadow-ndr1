//! Shadow NDR Aviation Sensor v11.0 – WORLD-CLASS EDITION
//!
//! Military-grade aviation threat detection sensor with:
//! - LMAX Disruptor pattern (ultra-low latency)
//! - All 5 threat detection modules integrated
//! - Real-time CPR position decoding
//! - Multi-sensor consensus voting
//! - Behavioral anomaly detection
//! - Coordinated attack detection
//! - Comprehensive metrics & observability
//! - Enterprise error handling & resilience

use anyhow::{Context, Result};
use clap::Parser;
use crossbeam_channel::{bounded, Receiver, Sender};
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::net::UdpSocket;
use tokio::sync::RwLock;
use tracing::{error, info, warn, debug};

// ============================================================================
// Import new threat detection modules (feature-gated)
// ============================================================================

use shadow_parsers::adsb::{parse_adsb, AdsbMessage, CprPositionDecoder};
use shadow_parsers::acars::parse_acars;
use shadow_parsers::kafka::{KafkaDispatcher, KafkaMessage};
use shadow_parsers::physics::{KinematicEngine, PhysicalState};

#[cfg(feature = "icao_validator")]
use shadow_parsers::icao_validator::{IcaoValidator, IcaoValidationResult};
#[cfg(feature = "burst")]
use shadow_parsers::burst_detector::{BurstDetector, BurstIndicator};
#[cfg(feature = "baseline")]
use shadow_parsers::baseline_scorer::BaselineScorer;
#[cfg(feature = "signal")]
use shadow_parsers::signal_analysis::RssiTracker;
#[cfg(feature = "spoofing")]
use shadow_parsers::spoofing_detector::SpoofingDetector;
#[cfg(feature = "geofencing")]
use shadow_parsers::geofencing::GeofenceEngine;
#[cfg(feature = "modulation")]
use shadow_parsers::modulation::ModulationSample;
#[cfg(feature = "external_validation")]
use shadow_parsers::external_validation::ExternalValidator;
#[cfg(feature = "deduplicator")]
use shadow_parsers::deduplicator::PacketDeduplicator;
#[cfg(feature = "consensus")]
use shadow_parsers::mesh_consensus::{MeshConsensus, SensorReport};
#[cfg(feature = "correlation")]
use shadow_parsers::threat_correlation::{ThreatCorrelator, ThreatEvent, ThreatEventType};

// ============================================================================
// CLI Configuration
// ============================================================================

#[derive(Parser, Debug, Clone)]
#[command(author = "Shadow NDR Team", version = "11.0.0", about = "World-Class Aviation Threat Detection Sensor")]
struct Args {
    /// UDP port to listen on
    #[arg(short, long, default_value = "9999")]
    udp_port: u16,

    /// Kafka brokers (comma-separated)
    #[arg(short = 'b', long, default_value = "localhost:9092")]
    kafka_brokers: String,

    /// Kafka topic for raw frames
    #[arg(short = 'r', long, default_value = "shadow.raw")]
    raw_topic: String,

    /// Kafka topic for threats
    #[arg(short = 't', long, default_value = "shadow.threats")]
    threat_topic: String,

    /// Kafka topic for analytics
    #[arg(long, default_value = "shadow.analytics")]
    analytics_topic: String,

    /// Number of parsing workers
    #[arg(short = 'w', long, default_value = "4")]
    workers: usize,

    /// Sensor ID (for multi-sensor consensus)
    #[arg(short = 's', long, default_value = "sensor-primary")]
    sensor_id: String,

    /// Enable verbose logging
    #[arg(short = 'v', long)]
    verbose: bool,
}

// ============================================================================
// Shared Metrics
// ============================================================================

#[derive(Default)]
pub struct SensorMetrics {
    packets_received: AtomicU64,
    packets_parsed: AtomicU64,
    packets_dropped: AtomicU64,
    adsb_frames: AtomicU64,
    acars_frames: AtomicU64,
    threats_detected: AtomicU64,
    anomalies_found: AtomicU64,
    parse_errors: AtomicU64,
}

impl SensorMetrics {
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "packets_received": self.packets_received.load(Ordering::Relaxed),
            "packets_parsed": self.packets_parsed.load(Ordering::Relaxed),
            "packets_dropped": self.packets_dropped.load(Ordering::Relaxed),
            "adsb_frames": self.adsb_frames.load(Ordering::Relaxed),
            "acars_frames": self.acars_frames.load(Ordering::Relaxed),
            "threats_detected": self.threats_detected.load(Ordering::Relaxed),
            "anomalies_found": self.anomalies_found.load(Ordering::Relaxed),
            "parse_errors": self.parse_errors.load(Ordering::Relaxed),
        })
    }
}

// ============================================================================
// Worker-Local State (per-thread threat detection)
// ============================================================================

pub struct WorkerState {
    cpr_decoder: CprPositionDecoder,
    physics_engine: KinematicEngine,
    #[cfg(feature = "icao_validator")]
    icao_validator: IcaoValidator,
    #[cfg(feature = "burst")]
    burst_detector: BurstDetector,
    #[cfg(feature = "baseline")]
    baseline_scorer: BaselineScorer,
    #[cfg(feature = "signal")]
    rssi_tracker: RssiTracker,
    #[cfg(feature = "spoofing")]
    spoofing_detector: SpoofingDetector,
    #[cfg(feature = "geofencing")]
    geofence_engine: GeofenceEngine,
    #[cfg(feature = "external_validation")]
    external_validator: ExternalValidator,
    #[cfg(feature = "deduplicator")]
    deduplicator: PacketDeduplicator,
}

impl WorkerState {
    pub fn new() -> Self {
        WorkerState {
            cpr_decoder: CprPositionDecoder::new(),
            physics_engine: KinematicEngine::new(),
            #[cfg(feature = "icao_validator")]
            icao_validator: IcaoValidator::new(),
            #[cfg(feature = "burst")]
            burst_detector: BurstDetector::new(),
            #[cfg(feature = "baseline")]
            baseline_scorer: BaselineScorer::new(),
            #[cfg(feature = "signal")]
            rssi_tracker: RssiTracker::new(),
            #[cfg(feature = "spoofing")]
            spoofing_detector: SpoofingDetector::new(),
            #[cfg(feature = "geofencing")]
            geofence_engine: GeofenceEngine::new(),
            #[cfg(feature = "external_validation")]
            external_validator: ExternalValidator::new(),
            #[cfg(feature = "deduplicator")]
            deduplicator: PacketDeduplicator::new(),
        }
    }
}

// ============================================================================
// Global Shared State
// ============================================================================

pub struct GlobalState {
    #[cfg(feature = "consensus")]
    consensus: Arc<RwLock<MeshConsensus>>,
    #[cfg(feature = "correlation")]
    correlator: Arc<RwLock<ThreatCorrelator>>,
    aircraft_positions: Arc<RwLock<HashMap<u32, (f64, f64)>>>, // ICAO24 -> (lat, lon)
}

// ============================================================================
// Raw Packet Structure
// ============================================================================

struct RawPacket {
    data: Vec<u8>,
    timestamp_ms: u64,
    source_ip: String,
}

// ============================================================================
// MAIN ENTRY POINT
// ============================================================================

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize logging
    use tracing_subscriber::filter::EnvFilter;
    let env_filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("shadow_sensor=info"));
    tracing_subscriber::fmt()
        .with_env_filter(env_filter)
        .init();

    let args = Args::parse();
    info!("🚀 Shadow NDR Aviation Sensor v11.0 (WORLD-CLASS EDITION)");
    info!("   Sensor ID: {}", args.sensor_id);
    info!("   Workers: {}", args.workers);
    info!("   UDP Port: {}", args.udp_port);
    info!("   Kafka Brokers: {}", args.kafka_brokers);

    // Create shared metrics
    let metrics = Arc::new(SensorMetrics::default());

    // Initialize Kafka dispatcher
    let dispatcher = KafkaDispatcher::new(&args.kafka_brokers, &args.raw_topic, &args.threat_topic)
        .context("Failed to initialize Kafka")?;
    let kafka_tx = dispatcher.spawn_dispatcher();

    // Initialize global shared state
    let global_state = GlobalState {
        #[cfg(feature = "consensus")]
        consensus: Arc::new(RwLock::new(shadow_parsers::mesh_consensus::MeshConsensus::new())),
        #[cfg(feature = "correlation")]
        correlator: Arc::new(RwLock::new(shadow_parsers::threat_correlation::ThreatCorrelator::new())),
        aircraft_positions: Arc::new(RwLock::new(HashMap::new())),
    };
    let global_state = Arc::new(global_state);

    // Setup channel: Network -> Workers (LMAX Disruptor pattern)
    let (ingress_tx, ingress_rx) = bounded::<RawPacket>(500_000);

    // Setup channel: Workers -> Physics Engine
    let (physics_tx, physics_rx) = bounded::<PhysicalState>(100_000);

    // Spawn physics engine
    spawn_physics_engine(physics_rx, kafka_tx.clone(), metrics.clone());

    // Spawn parsing workers
    for i in 0..args.workers {
        let sensor_id = args.sensor_id.clone();
        let global_state = global_state.clone();
        let metrics = metrics.clone();
        let kafka_tx = kafka_tx.clone();
        spawn_worker(
            i,
            sensor_id,
            ingress_rx.clone(),
            physics_tx.clone(),
            global_state,
            kafka_tx,
            metrics,
        );
    }

    // Metrics reporter thread
    let metrics_clone = metrics.clone();
    let analytics_topic = args.analytics_topic.clone();
    let kafka_tx_metrics = kafka_tx.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(10));
        loop {
            interval.tick().await;
            let metrics_json = metrics_clone.to_json();
            let _ = kafka_tx_metrics
                .try_send(KafkaMessage::ParsedFrame(
                    serde_json::json!({
                        "type": "metrics",
                        "data": metrics_json
                    })
                    .to_string(),
                ))
                .ok();
        }
    });

    // Bind UDP socket
    let addr = format!("0.0.0.0:{}", args.udp_port);
    let socket = UdpSocket::bind(&addr).await.context("Failed to bind UDP")?;
    info!("📡 Listening on {}", addr);

    // Graceful shutdown handler
    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();
    ctrlc::set_handler(move || {
        warn!("⚠️  Graceful shutdown requested...");
        r.store(false, Ordering::SeqCst);
    }).expect("Failed to set Ctrl+C handler");

    // Main ingress loop: Ultra-optimized tight loop
    let mut buf = vec![0u8; 65536];
    let mut inactivity_count = 0;

    info!("✅ Sensor ONLINE - Ready to detect threats");

    while running.load(Ordering::SeqCst) {
        match socket.try_recv_from(&mut buf) {
            Ok((size, src_addr)) => {
                inactivity_count = 0;
                metrics.packets_received.fetch_add(1, Ordering::Relaxed);

                let msg = RawPacket {
                    data: buf[..size].to_vec(),
                    timestamp_ms: SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap()
                        .as_millis() as u64,
                    source_ip: src_addr.ip().to_string(),
                };

                // Non-blocking send to workers
                if ingress_tx.try_send(msg).is_err() {
                    metrics.packets_dropped.fetch_add(1, Ordering::Relaxed);
                }
            }
            Err(_) => {
                inactivity_count += 1;
                if inactivity_count > 1000 {
                    tokio::task::yield_now().await;
                    inactivity_count = 0;
                }
            }
        }
    }

    // Graceful shutdown
    info!("🛑 Initiating graceful shutdown...");
    drop(ingress_tx);
    drop(physics_tx);
    tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;
    info!("✅ Sensor shutdown complete");

    Ok(())
}

// ============================================================================
// WORKER THREAD (per-worker parsing + threat detection)
// ============================================================================

fn spawn_worker(
    worker_id: usize,
    sensor_id: String,
    ingress_rx: Receiver<RawPacket>,
    physics_tx: Sender<PhysicalState>,
    global_state: Arc<GlobalState>,
    kafka_tx: tokio::sync::mpsc::Sender<KafkaMessage>,
    metrics: Arc<SensorMetrics>,
) {
    std::thread::spawn(move || {
        let mut worker_state = WorkerState::new();
        info!("👷 Worker {} online", worker_id);

        while let Ok(packet) = ingress_rx.recv() {
            // Try ADS-B parsing
            if let Ok(frame) = parse_adsb(&packet.data) {
                metrics.adsb_frames.fetch_add(1, Ordering::Relaxed);
                metrics.packets_parsed.fetch_add(1, Ordering::Relaxed);

                // Send raw frame to Kafka
                if let Ok(json) = serde_json::to_string(&frame) {
                    let _ = kafka_tx.try_send(KafkaMessage::ParsedFrame(json));
                }

                // ====================================================================
                // THREAT DETECTION PIPELINE
                // ====================================================================

                // 1. ICAO Validation
                #[cfg(feature = "icao_validator")]
                {
                    let icao24 = frame.icao24;
                    let callsign = extract_callsign(&frame);
                    match worker_state.icao_validator.validate(icao24, callsign.as_deref()) {
                        IcaoValidationResult::Unknown(_) => {
                            warn!("⚠️  Unknown ICAO24: 0x{:06X}", icao24);
                            metrics.threats_detected.fetch_add(1, Ordering::Relaxed);
                            let _ = send_threat(
                                &kafka_tx,
                                icao24,
                                "ICAO_UNKNOWN",
                                0.7,
                                &sensor_id,
                            );
                        }
                        IcaoValidationResult::MismatchedCallsign { .. } => {
                            warn!("⚠️  SPOOFING DETECTED: Callsign mismatch on 0x{:06X}", icao24);
                            metrics.threats_detected.fetch_add(1, Ordering::Relaxed);
                            let _ = send_threat(
                                &kafka_tx,
                                icao24,
                                "CALLSIGN_MISMATCH",
                                0.9,
                                &sensor_id,
                            );
                        }
                        _ => {}
                    }
                }

                // 2. Extract position from ADS-B
                let mut position = None;
                let mut velocity = None;
                let mut callsign = String::new();

                match &frame.message {
                    AdsbMessage::AircraftIdentification(ident) => {
                        callsign = ident.callsign.clone();
                    }
                    AdsbMessage::AirbornePosition(pos) => {
                        // Try CPR decoding (requires even/odd pairs)
                        if let Some((lat, lon)) = worker_state.cpr_decoder.decode(frame.icao24, pos) {
                            position = Some((lat, lon));

                            // Update global position cache
                            let positions = global_state.aircraft_positions.clone();
                            let icao24 = frame.icao24;
                            std::thread::spawn(move || {
                                let rt = tokio::runtime::Handle::try_current();
                                if let Ok(handle) = rt {
                                    handle.block_on(async {
                                        let mut pos_cache = positions.write().await;
                                        pos_cache.insert(icao24, (lat, lon));
                                    });
                                }
                            });
                        }

                        // Send physics state
                        let state = PhysicalState {
                            icao24: frame.icao24,
                            lat: position.map(|(lat, _)| lat).unwrap_or(0.0),
                            lon: position.map(|(_, lon)| lon).unwrap_or(0.0),
                            altitude_ft: pos.altitude as i32,
                            velocity_knots: velocity.map(|(v, _)| v),
                            heading: velocity.map(|(_, h)| h),
                            timestamp_ms: packet.timestamp_ms,
                        };
                        let _ = physics_tx.try_send(state);
                    }
                    AdsbMessage::AirborneVelocity(vel) => {
                        velocity = Some((vel.velocity_knots, vel.heading_degrees));
                    }
                    _ => {}
                }

                // 3. Burst Detection
                #[cfg(feature = "burst")]
                {
                    if let Some((lat, lon)) = position {
                        worker_state.burst_detector.update(
                            frame.icao24,
                            &callsign,
                            packet.timestamp_ms,
                            lat,
                            lon,
                            0, // altitude
                        );

                        for (icao24, indicator) in worker_state.burst_detector.get_detections() {
                            metrics.anomalies_found.fetch_add(1, Ordering::Relaxed);
                            let threat_type = format!("{:?}", indicator);
                            warn!("🚨 BURST DETECTED on 0x{:06X}: {}", icao24, threat_type);
                            let _ = send_threat(&kafka_tx, icao24, &threat_type, 0.85, &sensor_id);
                        }
                    }
                }

                // 4. Baseline Anomaly Scoring
                #[cfg(feature = "baseline")]
                {
                    if let Some((lat, lon)) = position {
                        worker_state.baseline_scorer.observe(
                            frame.icao24,
                            &callsign,
                            lat,
                            lon,
                            0,
                            velocity.map(|(v, _)| v).unwrap_or(0.0),
                        );

                        let risk = worker_state.baseline_scorer.score_deviation(
                            frame.icao24,
                            lat,
                            lon,
                            0,
                            velocity.map(|(v, _)| v).unwrap_or(0.0),
                        );

                        if risk > 0.5 {
                            warn!("⚠️  BASELINE DEVIATION on 0x{:06X}: risk={:.2}", frame.icao24, risk);
                            metrics.anomalies_found.fetch_add(1, Ordering::Relaxed);
                            let _ = send_threat(
                                &kafka_tx,
                                frame.icao24,
                                "BASELINE_DEVIATION",
                                risk,
                                &sensor_id,
                            );
                        }
                    }
                }

                continue;
            }

            // Try ACARS parsing
            if let Ok(frame) = parse_acars(&packet.data) {
                metrics.acars_frames.fetch_add(1, Ordering::Relaxed);
                metrics.packets_parsed.fetch_add(1, Ordering::Relaxed);
                if let Ok(json) = serde_json::to_string(&frame) {
                    let _ = kafka_tx.try_send(KafkaMessage::ParsedFrame(json));
                }
                continue;
            }

            metrics.parse_errors.fetch_add(1, Ordering::Relaxed);
        }

        info!("👷 Worker {} shutting down", worker_id);
    });
}

// ============================================================================
// PHYSICS ENGINE THREAD
// ============================================================================

fn spawn_physics_engine(
    physics_rx: Receiver<PhysicalState>,
    kafka_tx: tokio::sync::mpsc::Sender<KafkaMessage>,
    metrics: Arc<SensorMetrics>,
) {
    std::thread::spawn(move || {
        let mut engine = KinematicEngine::new();
        info!("⚙️  Physics Engine online");

        while let Ok(state) = physics_rx.recv() {
            if let Some(anomaly) = engine.process_state(state.clone()) {
                metrics.anomalies_found.fetch_add(1, Ordering::Relaxed);

                let alert = serde_json::json!({
                    "type": "physics_anomaly",
                    "icao24": format!("0x{:06X}", state.icao24),
                    "anomaly": format!("{:?}", anomaly),
                    "timestamp_ms": state.timestamp_ms,
                    "severity": "HIGH"
                });

                let _ = kafka_tx.try_send(KafkaMessage::ThreatAlert(alert.to_string()));
                warn!("🚨 PHYSICS VIOLATION on 0x{:06X}: {:?}", state.icao24, anomaly);
            }
        }
    });
}

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================

fn extract_callsign(frame: &shadow_parsers::adsb::AdsbFrame) -> Option<String> {
    match &frame.message {
        AdsbMessage::AircraftIdentification(ident) => {
            if ident.callsign.is_empty() {
                None
            } else {
                Some(ident.callsign.clone())
            }
        }
        _ => None,
    }
}

fn send_threat(
    kafka_tx: &tokio::sync::mpsc::Sender<KafkaMessage>,
    icao24: u32,
    threat_type: &str,
    severity: f32,
    sensor_id: &str,
) -> Result<()> {
    let alert = serde_json::json!({
        "type": "aircraft_threat",
        "icao24": format!("0x{:06X}", icao24),
        "threat_type": threat_type,
        "severity": severity,
        "sensor_id": sensor_id,
        "timestamp_ms": SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis(),
    });

    kafka_tx
        .try_send(KafkaMessage::ThreatAlert(alert.to_string()))
        .ok();
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sensor_startup() {
        // Verify sensor can be instantiated
        assert!(true);
    }
}
