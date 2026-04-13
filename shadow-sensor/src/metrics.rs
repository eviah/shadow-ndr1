use anyhow::Result;
use prometheus::{
    register_histogram, register_int_counter, IntCounter, Histogram, Registry, Encoder,
};
use dashmap::DashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::task::JoinHandle;
use tokio::sync::RwLock;
use std::collections::VecDeque;

pub struct Metrics {
    registry: Registry,
    
    // מונים בסיסיים
    packets_processed: IntCounter,
    parse_errors: IntCounter,
    packets_sent: IntCounter,
    compression_saved_bytes: IntCounter,
    retries_total: IntCounter,
    send_errors_total: IntCounter,
    
    // היסטוגרמות
    batch_process_duration: Histogram,
    batch_size_histogram: Histogram,
    
    // מונים סטטיים לפי פרוטוקול
    tcp_packets: IntCounter,
    udp_packets: IntCounter,
    dns_packets: IntCounter,
    other_packets: IntCounter,
    
    // מונים סטטיים לפי רמת איום
    threats_low: IntCounter,
    threats_medium: IntCounter,
    threats_high: IntCounter,
    threats_critical: IntCounter,
    
    // מונים דינמיים לפרוטוקולים ואיומים נוספים
    protocol_counters: DashMap<String, IntCounter>,
    threat_counters: DashMap<String, IntCounter>,
    
    // נתונים לחישוב קצב חבילות (rate limiting) – גרסה אסינכרונית
    packet_rate_queue: RwLock<VecDeque<(Instant, u64)>>,
    current_rate: RwLock<f64>,
}

impl Metrics {
    pub fn new() -> Result<Arc<Self>> {
        let registry = Registry::new();
        
        // רישום המונים הסטנדרטיים
        let packets_processed = register_int_counter!("shadow_packets_processed_total", "Total packets processed")?;
        let parse_errors = register_int_counter!("shadow_parse_errors_total", "Parse errors")?;
        let packets_sent = register_int_counter!("shadow_packets_sent_total", "Total packets sent")?;
        let compression_saved_bytes = register_int_counter!("shadow_compression_saved_bytes_total", "Bytes saved by compression")?;
        let retries_total = register_int_counter!("shadow_retries_total", "Total retries")?;
        let send_errors_total = register_int_counter!("shadow_send_errors_total", "Total send errors")?;
        
        let batch_process_duration = register_histogram!("shadow_batch_process_duration_seconds", "Batch processing duration")?;
        let batch_size_histogram = register_histogram!("shadow_batch_size_bytes", "Batch size in bytes")?;
        
        let tcp_packets = register_int_counter!("shadow_tcp_packets_total", "Total TCP packets")?;
        let udp_packets = register_int_counter!("shadow_udp_packets_total", "Total UDP packets")?;
        let dns_packets = register_int_counter!("shadow_dns_packets_total", "Total DNS packets")?;
        let other_packets = register_int_counter!("shadow_other_packets_total", "Total other packets")?;
        
        let threats_low = register_int_counter!("shadow_threats_low_total", "Low threats")?;
        let threats_medium = register_int_counter!("shadow_threats_medium_total", "Medium threats")?;
        let threats_high = register_int_counter!("shadow_threats_high_total", "High threats")?;
        let threats_critical = register_int_counter!("shadow_threats_critical_total", "Critical threats")?;
        
        // רישום כל המונים ב-registry
        registry.register(Box::new(packets_processed.clone()))?;
        registry.register(Box::new(parse_errors.clone()))?;
        registry.register(Box::new(packets_sent.clone()))?;
        registry.register(Box::new(compression_saved_bytes.clone()))?;
        registry.register(Box::new(retries_total.clone()))?;
        registry.register(Box::new(send_errors_total.clone()))?;
        registry.register(Box::new(batch_process_duration.clone()))?;
        registry.register(Box::new(batch_size_histogram.clone()))?;
        registry.register(Box::new(tcp_packets.clone()))?;
        registry.register(Box::new(udp_packets.clone()))?;
        registry.register(Box::new(dns_packets.clone()))?;
        registry.register(Box::new(other_packets.clone()))?;
        registry.register(Box::new(threats_low.clone()))?;
        registry.register(Box::new(threats_medium.clone()))?;
        registry.register(Box::new(threats_high.clone()))?;
        registry.register(Box::new(threats_critical.clone()))?;
        
        Ok(Arc::new(Self {
            registry,
            packets_processed,
            parse_errors,
            packets_sent,
            compression_saved_bytes,
            retries_total,
            send_errors_total,
            batch_process_duration,
            batch_size_histogram,
            tcp_packets,
            udp_packets,
            dns_packets,
            other_packets,
            threats_low,
            threats_medium,
            threats_high,
            threats_critical,
            protocol_counters: DashMap::new(),
            threat_counters: DashMap::new(),
            packet_rate_queue: RwLock::new(VecDeque::with_capacity(60)),
            current_rate: RwLock::new(0.0),
        }))
    }
    
    // ---------- מתודות אסינכרוניות לעדכון מונים ----------
    pub async fn inc_packets_processed(&self, count: u64) {
        self.packets_processed.inc_by(count);
        self.update_packet_rate(count).await;
    }
    
    // מתודות סינכרוניות – לא נוגעות ב-RwLock
    pub fn inc_parse_errors(&self) {
        self.parse_errors.inc();
    }
    
    pub fn inc_send_errors(&self) {
        self.send_errors_total.inc();
    }
    
    pub fn inc_retries(&self) {
        self.retries_total.inc();
    }
    
    pub fn inc_packets_sent(&self, count: u64) {
        self.packets_sent.inc_by(count);
    }
    
    pub fn add_compression_saved_bytes(&self, bytes: u64) {
        self.compression_saved_bytes.inc_by(bytes);
    }
    
    pub fn record_batch_size(&self, size: usize) {
        self.batch_size_histogram.observe(size as f64);
    }
    
    pub fn observe_batch_process_time(&self, duration: Duration) {
        self.batch_process_duration.observe(duration.as_secs_f64());
    }
    
    // ---------- מונים לפי פרוטוקול ----------
    pub fn inc_protocol_counter(&self, protocol: &str) {
        match protocol {
            "tcp" => self.tcp_packets.inc(),
            "udp" => self.udp_packets.inc(),
            "dns" => self.dns_packets.inc(),
            _ => self.other_packets.inc(),
        }
        let counter = self.protocol_counters
            .entry(protocol.to_string())
            .or_insert_with(|| {
                let name = format!("shadow_protocol_{}_total", protocol);
                let help = format!("Total {} packets", protocol);
                let c = register_int_counter!(name, help).unwrap();
                self.registry.register(Box::new(c.clone())).unwrap();
                c
            });
        counter.inc();
    }
    
    // ---------- מונים לפי רמת איום ----------
    pub fn inc_threat_counter(&self, threat: &str) {
        match threat {
            "low" => self.threats_low.inc(),
            "medium" => self.threats_medium.inc(),
            "high" => self.threats_high.inc(),
            "critical" => self.threats_critical.inc(),
            _ => {
                let counter = self.threat_counters
                    .entry(threat.to_string())
                    .or_insert_with(|| {
                        let name = format!("shadow_threat_{}_total", threat);
                        let help = format!("Total {} threats", threat);
                        let c = register_int_counter!(name, help).unwrap();
                        self.registry.register(Box::new(c.clone())).unwrap();
                        c
                    });
                counter.inc();
            }
        }
    }
    
    // ---------- חישוב קצב חבילות (load factor) – גרסה אסינכרונית ----------
    async fn update_packet_rate(&self, count: u64) {
        let now = Instant::now();
        let mut queue = self.packet_rate_queue.write().await;
        queue.push_back((now, count));
        
        // הסרת נתונים ישנים (מעל 60 שניות)
        while let Some((t, _)) = queue.front() {
            if now.duration_since(*t) > Duration::from_secs(60) {
                queue.pop_front();
            } else {
                break;
            }
        }
        
        // חישוב ממוצע החבילות בשנייה ב-60 השניות האחרונות
        let total_packets: u64 = queue.iter().map(|(_, c)| c).sum();
        let rate = total_packets as f64 / 60.0;
        *self.current_rate.write().await = rate;
    }
    
    pub async fn get_recent_packet_rate(&self) -> f64 {
        *self.current_rate.read().await
    }
    
    pub async fn get_current_load_factor(&self) -> f64 {
        let rate = self.get_recent_packet_rate().await;
        if rate > 10000.0 {
            1.0
        } else if rate > 5000.0 {
            0.75
        } else if rate > 1000.0 {
            0.5
        } else {
            0.3
        }
    }
    
    // ---------- HTTP server למטריקות ----------
    pub fn start_http_server(&self, port: u16) -> Result<JoinHandle<()>> {
        use axum::{routing::get, Router, http::StatusCode};
        use prometheus::TextEncoder;
        let registry = self.registry.clone();
        let registry = Arc::new(registry);
        let app = Router::new().route("/metrics", get(move || {
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
        }));
        let addr = std::net::SocketAddr::from(([0,0,0,0], port));
        let handle = tokio::spawn(async move {
            let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
            axum::serve(listener, app).await.unwrap();
        });
        Ok(handle)
    }
}