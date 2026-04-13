use anyhow::Result;
use clap::Parser;
#[cfg(feature = "kafka")]
use rdkafka::config::ClientConfig;
#[cfg(feature = "kafka")]
use rdkafka::producer::FutureProducer;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;

#[derive(Debug, Clone, Parser)]
#[command(author, version, about)]
pub struct Args {
    #[arg(short, long)]
    pub config: Option<PathBuf>,

    #[arg(short, long, env = "SHADOW_INTERFACE")]
    pub interfaces: Vec<String>,

    #[arg(short = 'b', long, env = "SHADOW_KAFKA_BROKERS")]
    pub kafka_brokers: Option<String>,

    #[arg(short = 't', long, default_value = "shadow.events")]
    pub kafka_topic: String,

    #[arg(long, default_value_t = 8081)]
    pub health_port: u16,

    #[arg(long, default_value_t = 9090)]
    pub metrics_port: u16,

    #[arg(long, default_value_t = 100000)]
    pub rate_limit_pps: u32,

    #[arg(long, default_value_t = 100)]
    pub batch_size: usize,

    #[arg(long, default_value_t = 500)]              // חדש: flush interval ms
    pub batch_flush_interval_ms: u64,

    #[arg(long)]
    pub enable_af_xdp: bool,

    #[arg(long)]
    pub bpf_filter: Option<String>,

    #[arg(long, default_value_t = true)]
    pub promisc: bool,

    #[arg(long, default_value_t = 65535)]
    pub snaplen: i32,

    // ---------- שדות חדשים ל-processor מתקדם ----------
    #[arg(long, default_value_t = 10)]
    pub max_concurrent_sends: usize,

    #[arg(long, default_value_t = 3)]
    pub retry_attempts: u32,

    #[arg(long, default_value_t = 100)]
    pub retry_base_delay_ms: u64,

    #[arg(long, default_value_t = 5)]
    pub send_timeout_secs: u64,

    #[arg(long, default_value_t = false)]
    pub compression_enabled: bool,

    #[arg(long, default_value_t = true)]
    pub dynamic_batching_enabled: bool,

    #[arg(long, default_value = "http://localhost:3001/api/sensor/data")]
    pub backend_url: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AppConfig {
    // קיים
    pub interfaces: Vec<String>,
    pub kafka_brokers: String,
    pub kafka_topic: String,
    pub health_port: u16,
    pub metrics_port: u16,
    pub rate_limit_pps: u32,
    pub batch_size: usize,
    pub batch_flush_interval_ms: u64,
    pub enable_af_xdp: bool,
    pub bpf_filter: Option<String>,
    pub promisc: bool,
    pub snaplen: i32,
    pub protocols: HashMap<String, bool>,

    // חדש
    pub max_concurrent_sends: usize,
    pub retry_attempts: u32,
    pub retry_base_delay_ms: u64,
    pub send_timeout_secs: u64,
    pub compression_enabled: bool,
    pub dynamic_batching_enabled: bool,
    pub backend_url: String,
}

impl Default for AppConfig {
    fn default() -> Self {
        let mut protocols = HashMap::new();
        for p in &[
            "adsb", "acars", "mode_s", "vdl", "cpdlc", "aeromacs", "iec104",
            "tcp", "udp", "icmp", "mqtt", "amqp", "modbus", "dnp3", "sip", "rtp", "dns", "dhcp"
        ] {
            protocols.insert(p.to_string(), true);
        }
        Self {
            interfaces: vec![],
            kafka_brokers: String::new(),
            kafka_topic: "shadow.events".to_string(),
            health_port: 8081,
            metrics_port: 9090,
            rate_limit_pps: 100_000,
            batch_size: 100,
            batch_flush_interval_ms: 500,
            enable_af_xdp: false,
            bpf_filter: None,
            promisc: true,
            snaplen: 65535,
            protocols,
            max_concurrent_sends: 2,
            retry_attempts: 3,
            retry_base_delay_ms: 100,
            send_timeout_secs: 5,
            compression_enabled: false,
            dynamic_batching_enabled: true,
            backend_url: "http://localhost:3001/api/sensor/data".to_string(),
        }
    }
}

impl AppConfig {
    pub fn load() -> Result<Self> {
        let args = Args::parse();
        let mut config = if let Some(path) = &args.config {
            let content = std::fs::read_to_string(path)?;
            serde_yaml::from_str(&content)?
        } else {
            Self::default()
        };

        // עדכון מ-CLI (מחליף את הערכים)
        if !args.interfaces.is_empty() {
            config.interfaces = args.interfaces;
        }
        if let Some(brokers) = args.kafka_brokers {
            config.kafka_brokers = brokers;
        }
        config.kafka_topic = args.kafka_topic;
        config.health_port = args.health_port;
        config.metrics_port = args.metrics_port;
        config.rate_limit_pps = args.rate_limit_pps;
        config.batch_size = args.batch_size;
        config.batch_flush_interval_ms = args.batch_flush_interval_ms;
        config.enable_af_xdp = args.enable_af_xdp;
        config.bpf_filter = args.bpf_filter;
        config.promisc = args.promisc;
        config.snaplen = args.snaplen;

        // עדכון שדות חדשים
        config.max_concurrent_sends = args.max_concurrent_sends;
        config.retry_attempts = args.retry_attempts;
        config.retry_base_delay_ms = args.retry_base_delay_ms;
        config.send_timeout_secs = args.send_timeout_secs;
        config.compression_enabled = args.compression_enabled;
        config.dynamic_batching_enabled = args.dynamic_batching_enabled;
        config.backend_url = args.backend_url;

        Ok(config)
    }

    pub fn kafka_enabled(&self) -> bool {
        !self.kafka_brokers.is_empty()
    }

    #[cfg(feature = "kafka")]
    pub fn build_kafka_producer(&self) -> Result<rdkafka::producer::FutureProducer> {
        let producer: rdkafka::producer::FutureProducer = ClientConfig::new()
            .set("bootstrap.servers", &self.kafka_brokers)
            .set("message.timeout.ms", "5000")
            .set("acks", "all")
            .set("compression.type", "snappy")
            .set("batch.size", "16384")
            .set("linger.ms", "10")
            .create()?;
        Ok(producer)
    }
}