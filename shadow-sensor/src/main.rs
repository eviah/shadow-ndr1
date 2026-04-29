//! Shadow NDR Ultimate Sensor – PRODUCTION GRADE
//!
//! Features:
//! - Graceful shutdown on SIGTERM/SIGINT (Ctrl+C)
//! - Structured tracing with `tracing` and `tracing-subscriber`
//! - Prometheus metrics & health HTTP servers
//! - Non‑blocking packet capture with `tokio`
//! - Zero‑copy, parallel parsing (Rayon)
//! - 20+ protocols (aviation, industrial, IoT, network)
//! - Kafka output (optional)
//! - AF_XDP / DPDK (optional)
//! - Periodic stats reporter with backpressure monitoring
//! - Resource cleanup and final statistics dump

mod capture;
mod config;
mod metrics;
mod processor;
mod parser;
mod threat;
mod protocols;

// ============================================================================
// WORLD-CLASS UPGRADES - Shadow Sensor v2.0
// ============================================================================
mod ai_engine;           // AI/ML Threat Intelligence
mod distributed_mesh;    // Multi-sensor distributed coordination
mod quantum_crypto;      // Post-quantum cryptography
mod threat_hunter;       // Automated threat hunting
mod hw_accel;           // Hardware acceleration (DPDK, AF_XDP, GPU)
mod analytics;          // Advanced real-time analytics engine
mod phantom_airspace;   // Honey-aircraft fleet + autonomous propagation
mod spsc_pipe;          // Lock-free SPSC ring + mmap-backed protobuf pipeline
mod dpi_matcher;        // SIMD Aho-Corasick multi-pattern DPI matcher
mod flow_table;         // Lock-free sharded flow table with Arc-reclamation
mod reassembly;         // TCP stream reassembly + IPv4 defragmentation
mod xdp_capture;        // AF_XDP zero-copy capture (UMEM-backed software stub off-Linux)
mod rule_jit;           // Compiled rule engine (bytecode VM, cranelift extension point)
mod hdr_telemetry;      // HDR histogram + per-flow telemetry bundles
mod hot_reload;         // Atomic-swap hot-reload rule engine (zero packet drop)
mod adaptive_sampler;   // PSI-style adaptive sampling under backpressure

use anyhow::Result;
use std::sync::Arc;
use tokio::signal;
use tracing::{info, error, warn};
use tracing_subscriber::{layer::SubscriberExt, EnvFilter, Registry};
use std::time::Duration;

#[tokio::main]
async fn main() -> Result<()> {
    // 1. Initialize structured logging (JSON + pretty console)
    let subscriber = Registry::default()
        .with(EnvFilter::from_default_env())
        .with(tracing_subscriber::fmt::layer()
            .with_target(true)
            .with_thread_ids(true)
            .json());
    tracing::subscriber::set_global_default(subscriber)?;

    info!(
        version = env!("CARGO_PKG_VERSION"),
        "🚀 Starting Shadow NDR Ultimate Sensor"
    );

    // 2. Load configuration (file, env, CLI)
    let config = match config::AppConfig::load() {
        Ok(cfg) => {
            info!(
                interfaces = ?cfg.interfaces,
                kafka_enabled = cfg.kafka_enabled(),
                "Configuration loaded successfully"
            );
            cfg
        }
        Err(e) => {
            error!(error = %e, "Failed to load configuration");
            return Err(e);
        }
    };

    // 3. Initialize Prometheus metrics server
    let metrics = metrics::Metrics::new()?;
    let metrics_handle = metrics.start_http_server(config.metrics_port)?;
    info!(port = config.metrics_port, "📊 Metrics endpoint");

    // 4. Initialize World-Class Upgrade Engines
    let ai_engine = ai_engine::AIThreatEngine::new(0.75);
    info!("🤖 AI Threat Intelligence Engine initialized (sensitivity=0.75)");

    let distributed_mesh = distributed_mesh::DistributedMesh::new("sensor-primary".to_string());
    info!("🌐 Distributed Mesh Network initialized");

    let quantum_crypto = quantum_crypto::QuantumCryptoEngine::new(true, "Kyber1024".to_string());
    info!("🔐 Quantum-Ready Cryptography (hybrid PQC) initialized");

    let threat_hunter = threat_hunter::ThreatHunter::new();
    info!("🔍 Automated Threat Hunting Engine initialized");

    let mut hw_accel = hw_accel::HardwareAccelerator::new(hw_accel::AccelerationConfig::default());
    match hw_accel.initialize().await {
        Ok(msg) => info!("⚡ Hardware Acceleration: {}", msg),
        Err(e) => warn!("⚠️ Hardware Acceleration unavailable: {}", e),
    }

    let analytics = analytics::AnalyticsEngine::new();
    info!("📊 Advanced Analytics Engine initialized");

    // 5. Create packet processor (shared across capture threads)
    let processor = match processor::PacketProcessor::new(Arc::clone(&metrics), config.clone()).await {
        Ok(p) => {
            info!("Packet processor initialized (retry={}, batch={})",
                  config.retry_attempts, config.batch_size);
            Arc::new(p)
        }
        Err(e) => {
            error!(error = %e, "Failed to create packet processor");
            return Err(e);
        }
    };

    // 5. Start periodic stats reporter (every 30 seconds)
    let stats_processor = Arc::clone(&processor);
    let stats_handle = tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(30));
        loop {
            interval.tick().await;
            let stats = stats_processor.stats().await;
            info!(
                packets_processed = stats.packets_processed,
                packets_sent = stats.packets_sent,
                parse_errors = stats.parse_errors,
                send_errors = stats.send_errors,
                retries = stats.retries,
                compression_saved_bytes = stats.compression_saved_bytes,
                avg_batch_size = stats.avg_batch_size,
                "📈 Sensor statistics"
            );
            // Update Prometheus gauges if needed
            // metrics.set_packets_processed(stats.packets_processed);
            // metrics.set_send_errors(stats.send_errors);
        }
    });

    // 6. Initialize capture engine
    let mut capture = match capture::CaptureEngine::new(config.clone(), Arc::clone(&processor)).await {
        Ok(cap) => {
            info!("Capture engine created");
            cap
        }
        Err(e) => {
            error!(error = %e, "Failed to initialize capture engine");
            return Err(e);
        }
    };

    // 7. Start health check server (for k8s readiness/liveness)
    let health_handle = match capture.start_health_server(config.health_port) {
        Ok(h) => {
            info!(port = config.health_port, "💚 Health endpoint");
            h
        }
        Err(e) => {
            error!(error = %e, "Failed to start health server");
            return Err(e);
        }
    };

    // 8. Graceful shutdown channel
    let (shutdown_tx, mut shutdown_rx) = tokio::sync::watch::channel(false);
    let _shutdown_tx_clone = shutdown_tx.clone();

    // 9. Handle SIGINT (Ctrl+C)
    tokio::spawn(async move {
        match signal::ctrl_c().await {
            Ok(()) => {
                info!("🛑 Received SIGINT (Ctrl+C), initiating graceful shutdown...");
                let _ = shutdown_tx.send(true);
            }
            Err(e) => {
                error!(error = %e, "Unable to listen for SIGINT");
            }
        }
    });

    // 10. Handle SIGTERM (Unix only – for Kubernetes/Docker)
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        let mut sigterm = match signal(SignalKind::terminate()) {
            Ok(s) => s,
            Err(e) => {
                error!(error = %e, "Failed to install SIGTERM handler");
                return;
            }
        };
        let shutdown_tx_sigterm = shutdown_tx_clone.clone();
        tokio::spawn(async move {
            sigterm.recv().await;
            info!("🛑 Received SIGTERM, initiating graceful shutdown...");
            let _ = shutdown_tx_sigterm.send(true);
        });
    }

    // 11. Run capture (blocks until shutdown)
    info!("📡 Starting packet capture...");
    tokio::select! {
        result = capture.run() => {
            match result {
                Ok(_) => info!("Capture engine stopped normally."),
                Err(e) => error!(error = %e, "Capture engine encountered an error"),
            }
        }
        _ = shutdown_rx.changed() => {
            warn!("Shutdown signal received, stopping capture...");
        }
    }

    // 12. Graceful shutdown sequence
    info!("🧹 Performing graceful shutdown...");

    // Stop capturing new packets
    if let Err(e) = capture.stop().await {
        error!(error = %e, "Error stopping capture engine");
    }

    // Flush all pending packets to backend (retry, backpressure)
    processor.flush().await;
    info!("✅ Processor flushed");

    // Give some time for in-flight HTTP requests to complete
    tokio::time::sleep(Duration::from_secs(2)).await;

    // 13. Dump final statistics to console and logs
    let final_stats = processor.stats().await;
    info!(
        "📊 FINAL STATISTICS:\n\
         ┌────────────────────────────────────────────┐\n\
         │ Packets Processed  {:>20} │\n\
         │ Packets Sent       {:>20} │\n\
         │ Parse Errors       {:>20} │\n\
         │ Send Errors        {:>20} │\n\
         │ Retries            {:>20} │\n\
         │ Compression Saved  {:>20} bytes │\n\
         │ Avg Batch Size     {:>20.2} │\n\
         └────────────────────────────────────────────┘",
        final_stats.packets_processed,
        final_stats.packets_sent,
        final_stats.parse_errors,
        final_stats.send_errors,
        final_stats.retries,
        final_stats.compression_saved_bytes,
        final_stats.avg_batch_size
    );

    // 14. Cancel background tasks
    stats_handle.abort();
    metrics_handle.abort();
    health_handle.abort();

    // 15. Optional: flush Kafka if enabled
    // #[cfg(feature = "kafka")]
    // if let Some(producer) = capture.kafka_producer() {
    //     info!("📤 Flushing Kafka producer...");
    //     let _ = producer.flush(Duration::from_secs(5));
    // }

    info!("👋 Shadow NDR Sensor stopped cleanly.");
    Ok(())
}