//! Shadow NDR Kafka Dispatch Engine (Mock)
//!
//! Provides asynchronous message dispatch capability.
//! Currently a mock implementation that can be replaced with rdkafka integration.

use anyhow::Result;
use tracing::{debug, info};
use std::time::Duration;
use tokio::sync::mpsc;
use tokio::time;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

/// Maximum payload size we expect in JSON (used for pre-allocating strings)
const PAYLOAD_ALLOC: usize = 1024;

/// Enum for messages bound for Kafka
#[derive(Debug)]
pub enum KafkaMessage {
    /// A parsed protocol frame (JSON serialized externally or internally)
    ParsedFrame(String),
    /// A physics anomaly or critical threat
    ThreatAlert(String),
}

/// The asynchronous publisher service (mock implementation)
pub struct KafkaDispatcher {
    raw_topic: String,
    threat_topic: String,
    message_count: Arc<AtomicU64>,
}

impl KafkaDispatcher {
    /// Initialize a new non-blocking Kafka dispatcher.
    pub fn new(brokers: &str, raw_topic: &str, threat_topic: &str) -> Result<Self> {
        info!("Kafka dispatcher initialized (mock) against brokers: {}", brokers);

        Ok(Self {
            raw_topic: raw_topic.to_string(),
            threat_topic: threat_topic.to_string(),
            message_count: Arc::new(AtomicU64::new(0)),
        })
    }

    /// Spawns a background task that listens on an MPSC channel and dispatches messages.
    /// Returns the Sender so workers can enqueue messages.
    pub fn spawn_dispatcher(self) -> mpsc::Sender<KafkaMessage> {
        let (tx, mut rx) = mpsc::channel::<KafkaMessage>(100_000);
        let message_count = Arc::clone(&self.message_count);
        let raw_topic = self.raw_topic.clone();
        let threat_topic = self.threat_topic.clone();

        tokio::spawn(async move {
            info!("Kafka dispatcher task started.");
            let mut flush_interval = time::interval(Duration::from_millis(500));
            let mut local_count = 0u64;

            loop {
                tokio::select! {
                    msg = rx.recv() => {
                        match msg {
                            Some(KafkaMessage::ParsedFrame(_payload)) => {
                                debug!("Dispatching raw frame to topic: {}", raw_topic);
                                local_count += 1;
                                message_count.fetch_add(1, Ordering::Relaxed);
                            }
                            Some(KafkaMessage::ThreatAlert(_payload)) => {
                                debug!("Dispatching threat alert to topic: {}", threat_topic);
                                local_count += 1;
                                message_count.fetch_add(1, Ordering::Relaxed);
                            }
                            None => {
                                info!("Kafka dispatcher channel closed. Total messages: {}", local_count);
                                break;
                            }
                        }
                    }
                    _ = flush_interval.tick() => {
                        // Periodic heartbeat could be added here
                    }
                }
            }

            info!("Kafka dispatcher shutdown complete.");
        });

        tx
    }

    /// Get message count (mock statistic)
    pub fn message_count(&self) -> u64 {
        self.message_count.load(Ordering::Relaxed)
    }
}
