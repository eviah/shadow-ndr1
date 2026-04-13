use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use bytes::Bytes;
#[cfg(feature = "compression-gzip")]
use flate2::write::GzEncoder;
#[cfg(feature = "compression-gzip")]
use flate2::Compression;
use rayon::prelude::*;
use tokio::sync::{RwLock, Semaphore, mpsc};
use tokio::time::sleep;
use tracing::{debug, error, warn};
use reqwest::Client;

use crate::config::AppConfig;
use crate::metrics::Metrics;
use crate::parser::{parse_packet, ParsedPacket};

// ---------- סטטיסטיקות מערכת ----------
#[derive(Default, Clone, serde::Serialize)]
pub struct ProcessorStats {
    pub packets_processed: u64,
    pub packets_sent: u64,
    pub parse_errors: u64,
    pub send_errors: u64,
    pub retries: u64,
    pub compression_saved_bytes: u64,
    pub queue_backpressure_count: u64,
    pub avg_batch_size: f64,
}

// ---------- המעבד הראשי ----------
pub struct PacketProcessor {
    metrics: Arc<Metrics>,
    config: Arc<AppConfig>,
    http_client: Client,
    backend_url: String,
    semaphore: Arc<Semaphore>,
    retry_attempts: u32,
    retry_base_delay: Duration,
    send_timeout: Duration,
    enabled_protocols: Arc<HashMap<String, bool>>,
    compression_enabled: bool,
    dynamic_batching: bool,
    batch_channel_tx: Option<mpsc::UnboundedSender<Vec<u8>>>,
    batch_handle: Option<tokio::task::JoinHandle<()>>,
    #[cfg(feature = "kafka")]
    kafka_producer: Option<Arc<rdkafka::producer::FutureProducer>>,
    stats: Arc<RwLock<ProcessorStats>>,
}

impl PacketProcessor {
    pub async fn new(metrics: Arc<Metrics>, config: AppConfig) -> Result<Self, anyhow::Error> {
        let max_concurrent_sends = config.max_concurrent_sends;
        let semaphore = Arc::new(Semaphore::new(max_concurrent_sends));
        let enabled_protocols = Arc::new(config.protocols.clone());

        let (tx, rx) = mpsc::unbounded_channel();
        let handle = Self::start_batch_worker(rx, metrics.clone(), Arc::new(config.clone()));

        let http_client = Client::builder()
            .timeout(Duration::from_secs(config.send_timeout_secs + 2))
            .pool_max_idle_per_host(20)
            .pool_idle_timeout(Duration::from_secs(30))
            .tcp_keepalive(Some(Duration::from_secs(60)))
            .build()?;

        Ok(Self {
            metrics: metrics.clone(),
            config: Arc::new(config.clone()),
            http_client,
            backend_url: config.backend_url.clone(),
            semaphore,
            retry_attempts: config.retry_attempts,
            retry_base_delay: Duration::from_millis(config.retry_base_delay_ms),
            send_timeout: Duration::from_secs(config.send_timeout_secs),
            enabled_protocols,
            compression_enabled: false,
            dynamic_batching: true,
            batch_channel_tx: Some(tx),
            batch_handle: Some(handle),
            #[cfg(feature = "kafka")]
            kafka_producer: None,
            stats: Arc::new(RwLock::new(ProcessorStats::default())),
        })
    }

    pub async fn get_load_factor(&self) -> f64 {
        let stats = self.stats.read().await;
        if stats.packets_processed < 1000 {
            0.5
        } else {
            // אם רוצים להשתמש בעומס אמיתי מה-Metrics:
            // self.metrics.get_current_load_factor().await
            1.0
        }
    }

    /// Worker לאיסוף חבילות לבאצ'ים חכמים
    fn start_batch_worker(
        mut rx: mpsc::UnboundedReceiver<Vec<u8>>,
        metrics: Arc<Metrics>,
        config: Arc<AppConfig>,
    ) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            let mut batch = Vec::with_capacity(config.batch_size);
            let mut last_flush = Instant::now();
            let flush_interval = Duration::from_millis(config.batch_flush_interval_ms);

            while let Some(packet) = rx.recv().await {
                batch.push(packet);
                let current_batch_size = batch.len();
                let dynamic_threshold = if config.dynamic_batching_enabled {
                    // ✅ תיקון: הוספת .await
                    (config.batch_size as f64 * metrics.get_current_load_factor().await).ceil() as usize
                } else {
                    config.batch_size
                };

                if current_batch_size >= dynamic_threshold || last_flush.elapsed() >= flush_interval {
                    let batch_to_send = std::mem::take(&mut batch);
                    if !batch_to_send.is_empty() {
                        metrics.record_batch_size(batch_to_send.len());
                    }
                    last_flush = Instant::now();
                }
            }
        })
    }

    #[cfg(feature = "compression-gzip")]
    async fn send_compressed(&self, packet: &ParsedPacket) -> Result<Vec<u8>, anyhow::Error> {
        if !self.compression_enabled {
            return Ok(serde_json::to_vec(packet)?);
        }
        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        serde_json::to_writer(&mut encoder, packet)?;
        let compressed = encoder.finish()?;
        let saved = serde_json::to_vec(packet)?.len() - compressed.len();
        if saved > 0 {
            let mut stats = self.stats.write().await;
            stats.compression_saved_bytes += saved as u64;
        }
        Ok(compressed)
    }

    async fn send_to_backend_with_retry(&self, packet: &ParsedPacket) -> Result<(), anyhow::Error> {
        let json_bytes = serde_json::to_vec(packet)?;

        let payload_str = String::from_utf8_lossy(&json_bytes);
        if payload_str.len() > 2 {
            debug!("[DEBUG] Sending packet - Protocol: {}, FlowID: {}, Payload size: {} bytes",
                   packet.protocol, packet.flow_id, json_bytes.len());
            debug!("[DEBUG] Payload preview: {}",
                   &payload_str[..std::cmp::min(300, payload_str.len())]);
        }

        let mut attempt = 0;
        let mut delay = self.retry_base_delay;
        let mut retries_used = 0;

        loop {
            attempt += 1;
            let send_future = self.http_client
                .post(&self.backend_url)
                .header("Content-Type", "application/json")
                .body(json_bytes.clone())
                .send();

            match tokio::time::timeout(self.send_timeout, send_future).await {
                Ok(Ok(response)) if response.status().is_success() => {
                    if retries_used > 0 {
                        let mut stats = self.stats.write().await;
                        stats.retries += retries_used as u64;
                        self.metrics.inc_retries();
                    }
                    debug!("[DEBUG] ✓ Packet sent successfully (attempt {}), Status: {}",
                           attempt, response.status());
                    return Ok(());
                }
                Ok(Ok(response)) => {
                    let status = response.status();
                    let err_msg = format!("Backend {}", status);
                    if attempt >= self.retry_attempts {
                        error!("[DEBUG] ✗ {} after {} attempts for packet: {}",
                               err_msg, attempt, packet.flow_id);
                        self.metrics.inc_send_errors();
                        return Err(anyhow::anyhow!(err_msg));
                    }
                    warn!("[DEBUG] {} (attempt {}), retrying in {:?}...", err_msg, attempt, delay);
                    retries_used += 1;
                }
                Ok(Err(e)) => {
                    if attempt >= self.retry_attempts {
                        error!("HTTP error: {}", e);
                        self.metrics.inc_send_errors();
                        return Err(e.into());
                    }
                    warn!("HTTP error: {}, retry {} in {:?}", e, attempt, delay);
                    retries_used += 1;
                }
                Err(_) => {
                    if attempt >= self.retry_attempts {
                        error!("Timeout after {} attempts", attempt);
                        self.metrics.inc_send_errors();
                        return Err(anyhow::anyhow!("send timeout"));
                    }
                    warn!("Timeout, retry {} in {:?}", attempt, delay);
                    retries_used += 1;
                }
            }
            sleep(delay).await;
            delay = std::cmp::min(delay * 2, Duration::from_secs(30));
        }
    }

    pub async fn process_batch(&self, batch: Vec<Vec<u8>>) {
        let start = Instant::now();
        let batch_len = batch.len();
        if batch_len == 0 { return; }

        let available_permits = self.semaphore.available_permits();
        if available_permits < 5 && batch_len > 500 {
            let mut stats = self.stats.write().await;
            stats.queue_backpressure_count += 1;
            drop(stats);
            warn!("Backpressure activated: only {} permits left", available_permits);
            sleep(Duration::from_millis(50)).await;
        }

        let parsed: Vec<Option<ParsedPacket>> = batch
            .par_iter()
            .map(|data| {
                let bytes = Bytes::copy_from_slice(data);
                parse_packet(&bytes, &self.enabled_protocols)
            })
            .collect();

        let mut parsed_count = 0;
        let mut send_handles = Vec::with_capacity(batch_len);
        let mut stats_guard = self.stats.write().await;

        for maybe_packet in parsed {
            match maybe_packet {
                Some(packet) => {
                    parsed_count += 1;
                    stats_guard.packets_processed += 1;
                    self.metrics.inc_protocol_counter(&packet.protocol);
                    if let Some(level) = &packet.threat_level {
                        self.metrics.inc_threat_counter(level);
                    }

                    let sem_clone = self.semaphore.clone();
                    let this_clone = self.clone();
                    let packet_clone = packet.clone();
                    let handle = tokio::spawn(async move {
                        let _permit = sem_clone.acquire().await.expect("semaphore closed");
                        this_clone.send_to_backend_with_retry(&packet_clone).await
                    });
                    send_handles.push(handle);
                }
                None => {
                    stats_guard.parse_errors += 1;
                    self.metrics.inc_parse_errors();
                }
            }
        }
        drop(stats_guard);

        let mut success = 0;
        let mut fail = 0;
        for handle in send_handles {
            match handle.await {
                Ok(Ok(_)) => success += 1,
                Ok(Err(_)) => fail += 1,
                Err(e) => {
                    fail += 1;
                    error!("Task panic: {}", e);
                }
            }
        }

        let mut stats = self.stats.write().await;
        stats.packets_sent += success;
        stats.send_errors += fail;
        stats.avg_batch_size = (stats.avg_batch_size * 0.9) + (batch_len as f64 * 0.1);
        drop(stats);

        let elapsed = start.elapsed();
        self.metrics.observe_batch_process_time(elapsed);
        // ✅ תיקון: הוספת .await לקריאה האסינכרונית
        self.metrics.inc_packets_processed(parsed_count as u64).await;
        debug!(
            "Batch: len={}, parsed={}, ok={}, fail={} in {:?}",
            batch_len, parsed_count, success, fail, elapsed
        );
    }

    pub fn push_packet(&self, data: Vec<u8>) -> Result<(), anyhow::Error> {
        if let Some(tx) = &self.batch_channel_tx {
            tx.send(data).map_err(|_| anyhow::anyhow!("batch channel closed"))?;
        }
        Ok(())
    }

    pub async fn flush(&self) {
        tokio::time::sleep(Duration::from_millis(500)).await;
    }

    pub async fn stats(&self) -> ProcessorStats {
        self.stats.read().await.clone()
    }
}

impl Clone for PacketProcessor {
    fn clone(&self) -> Self {
        Self {
            metrics: self.metrics.clone(),
            config: self.config.clone(),
            http_client: self.http_client.clone(),
            backend_url: self.backend_url.clone(),
            semaphore: self.semaphore.clone(),
            retry_attempts: self.retry_attempts,
            retry_base_delay: self.retry_base_delay,
            send_timeout: self.send_timeout,
            enabled_protocols: self.enabled_protocols.clone(),
            compression_enabled: self.compression_enabled,
            dynamic_batching: self.dynamic_batching,
            batch_channel_tx: None,
            batch_handle: None,
            #[cfg(feature = "kafka")]
            kafka_producer: self.kafka_producer.clone(),
            stats: self.stats.clone(),
        }
    }
}

impl Drop for PacketProcessor {
    fn drop(&mut self) {
        if let Some(handle) = self.batch_handle.take() {
            handle.abort();
        }
    }
}