use anyhow::Result;
use prometheus::{
    register_gauge, register_histogram, register_int_counter, register_int_gauge,
    Gauge, Histogram, IntCounter, IntGauge, Registry, Encoder,
};
use dashmap::DashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::task::JoinHandle;

pub struct Metrics {
    registry: Registry,

    // Counters (monotonic)
    packets_processed: IntCounter,
    packets_sent: IntCounter,
    parse_errors: IntCounter,
    send_errors: IntCounter,
    retries: IntCounter,
    compression_saved_bytes: IntCounter,
    dropped_rate_limit: IntCounter,
    dropped_backpressure: IntCounter,

    // Gauges (current values)
    current_load_factor: Gauge,
    current_batch_size: IntGauge,

    // Histograms
    batch_process_duration: Histogram,
    batch_size_distribution: Histogram, // גודל הבאצ'ים

    // Dynamic counters for protocols and threats
    protocol_counters: DashMap<String, IntCounter>,
    threat_counters: DashMap<String, IntCounter>,
}

impl Metrics {
    pub fn new() -> Result<Arc<Self>> {
        let registry = Registry::new();

        // Counters
        let packets_processed = register_int_counter!(
            "shadow_packets_processed_total",
            "Total packets successfully parsed"
        )?;
        let packets_sent = register_int_counter!(
            "shadow_packets_sent_total",
            "Total packets sent to backend"
        )?;
        let parse_errors = register_int_counter!(
            "shadow_parse_errors_total",
            "Total packets that failed parsing"
        )?;
        let send_errors = register_int_counter!(
            "shadow_send_errors_total",
            "Total packets that failed to send after retries"
        )?;
        let retries = register_int_counter!(
            "shadow_retries_total",
            "Total retry attempts when sending"
        )?;
        let compression_saved_bytes = register_int_counter!(
            "shadow_compression_saved_bytes_total",
            "Total bytes saved by compression (original - compressed)"
        )?;
        let dropped_rate_limit = register_int_counter!(
            "shadow_dropped_rate_limit_total",
            "Packets dropped due to rate limiting"
        )?;
        let dropped_backpressure = register_int_counter!(
            "shadow_dropped_backpressure_total",
            "Packets dropped due to channel backpressure"
        )?;

        // Gauges
        let current_load_factor = register_gauge!(
            "shadow_current_load_factor",
            "Current load factor (0..2) used for dynamic batching"
        )?;
        let current_batch_size = register_int_gauge!(
            "shadow_current_batch_size",
            "Current batch size (number of packets in current batch)"
        )?;

        // Histograms
        let batch_process_duration = register_histogram!(
            "shadow_batch_process_duration_seconds",
            "Time spent processing a batch (parsing + sending)"
        )?;
        let batch_size_distribution = register_histogram!(
            "shadow_batch_size_distribution",
            "Size of batches processed",
            vec![1.0, 10.0, 50.0, 100.0, 500.0, 1000.0, 5000.0, 10000.0]
        )?;

        // Register all
        registry.register(Box::new(packets_processed.clone()))?;
        registry.register(Box::new(packets_sent.clone()))?;
        registry.register(Box::new(parse_errors.clone()))?;
        registry.register(Box::new(send_errors.clone()))?;
        registry.register(Box::new(retries.clone()))?;
        registry.register(Box::new(compression_saved_bytes.clone()))?;
        registry.register(Box::new(dropped_rate_limit.clone()))?;
        registry.register(Box::new(dropped_backpressure.clone()))?;
        registry.register(Box::new(current_load_factor.clone()))?;
        registry.register(Box::new(current_batch_size.clone()))?;
        registry.register(Box::new(batch_process_duration.clone()))?;
        registry.register(Box::new(batch_size_distribution.clone()))?;

        Ok(Arc::new(Self {
            registry,
            packets_processed,
            packets_sent,
            parse_errors,
            send_errors,
            retries,
            compression_saved_bytes,
            dropped_rate_limit,
            dropped_backpressure,
            current_load_factor,
            current_batch_size,
            batch_process_duration,
            batch_size_distribution,
            protocol_counters: DashMap::new(),
            threat_counters: DashMap::new(),
        }))
    }

    // ---------- Counter increment helpers ----------
    pub fn inc_packets_processed(&self, n: u64) {
        self.packets_processed.inc_by(n);
    }

    pub fn inc_packets_sent(&self, n: u64) {
        self.packets_sent.inc_by(n);
    }

    pub fn inc_parse_errors(&self) {
        self.parse_errors.inc();
    }

    pub fn inc_send_errors(&self) {
        self.send_errors.inc();
    }

    pub fn inc_retries(&self) {
        self.retries.inc();
    }

    pub fn add_compression_saved_bytes(&self, bytes: u64) {
        self.compression_saved_bytes.inc_by(bytes);
    }

    pub fn inc_dropped_rate_limit(&self) {
        self.dropped_rate_limit.inc();
    }

    pub fn inc_dropped_backpressure(&self) {
        self.dropped_backpressure.inc();
    }

    // ---------- Gauge setters ----------
    pub fn set_load_factor(&self, value: f64) {
        self.current_load_factor.set(value);
    }

    pub fn set_current_batch_size(&self, size: i64) {
        self.current_batch_size.set(size);
    }

    // ---------- Protocol & Threat counters (lazy registration) ----------
    pub fn inc_protocol_counter(&self, protocol: &str) {
        let counter = self.protocol_counters
            .entry(protocol.to_string())
            .or_insert_with(|| {
                let c = register_int_counter!(
                    format!("shadow_protocol_{}_total", protocol),
                    format!("Total {} packets", protocol)
                ).unwrap();
                self.registry.register(Box::new(c.clone())).unwrap();
                c
            });
        counter.inc();
    }

    pub fn inc_threat_counter(&self, threat: &str) {
        let counter = self.threat_counters
            .entry(threat.to_string())
            .or_insert_with(|| {
                let c = register_int_counter!(
                    format!("shadow_threat_{}_total", threat),
                    format!("Total {} threats", threat)
                ).unwrap();
                self.registry.register(Box::new(c.clone())).unwrap();
                c
            });
        counter.inc();
    }

    // ---------- Histogram observations ----------
    pub fn observe_batch_process_time(&self, duration: Duration) {
        self.batch_process_duration.observe(duration.as_secs_f64());
    }

    pub fn observe_batch_size(&self, size: usize) {
        self.batch_size_distribution.observe(size as f64);
    }

    // ---------- HTTP server ----------
    pub fn start_http_server(&self, port: u16) -> Result<JoinHandle<()>> {
        use axum::{routing::get, Router, http::StatusCode};
        use prometheus::TextEncoder;
        let registry = self.registry.clone();
        let registry = Arc::new(registry);
        let app = Router::new().route("/metrics", get({
            let registry = registry.clone();
            move || {
                let registry = registry.clone();
                async move {
                    let encoder = TextEncoder::new();
                    let metric_families = registry.gather();
                    let mut buffer = vec![];
                    if encoder.encode(&metric_families, &mut buffer).is_err() {
                        return (StatusCode::INTERNAL_SERVER_ERROR, "Failed to encode metrics".to_string());
                    }
                    match String::from_utf8(buffer) {
                        Ok(s) => (StatusCode::OK, s),
                        Err(_) => (StatusCode::INTERNAL_SERVER_ERROR, "Failed to encode metrics".to_string()),
                    }
                }
            }
        }));
        let addr = std::net::SocketAddr::from(([0,0,0,0], port));
        let handle = tokio::spawn(async move {
            let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
            axum::serve(listener, app).await.unwrap();
        });
        Ok(handle)
    }
}