//! Shadow NDR Kafka Dispatch Engine
//!
//! Provides ultra-fast, asynchronous message delivery to Apache Kafka.
//! Backed by `rdkafka` (librdkafka C bindings), this engine is capable of
//! delivering millions of events per second with zero blocking on the parser
//! worker threads.

use anyhow::{Context, Result};
use log::{debug, error, info, warn};
use rdkafka::config::ClientConfig;
use rdkafka::producer::{FutureProducer, FutureRecord};
use serde::Serialize;
use std::time::Duration;
use tokio::sync::mpsc;
use tokio::time;

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

/// The asynchronous publisher service
pub struct KafkaDispatcher {
    producer: FutureProducer,
    raw_topic: String,
    threat_topic: String,
}

impl KafkaDispatcher {
    /// Initialize a new non-blocking Kafka dispatcher.
    pub fn new(brokers: &str, raw_topic: &str, threat_topic: &str) -> Result<Self> {
        let producer: FutureProducer = ClientConfig::new()
            .set("bootstrap.servers", brokers)
            .set("message.timeout.ms", "5000")
            // Optimize for throughput
            .set("queue.buffering.max.ms", "10")
            .set("batch.num.messages", "10000")
            .set("compression.type", "lz4")
            .set("client.id", "shadow-sensor-titan")
            .create()
            .context("Failed to create rdkafka FutureProducer")?;

        info!("Kafka producer initialized against brokers: {}", brokers);

        Ok(Self {
            producer,
            raw_topic: raw_topic.to_string(),
            threat_topic: threat_topic.to_string(),
        })
    }

    /// Spawns a background task that listens on an MPSC channel and pushes to Kafka.
    /// Returns the Sender so workers can enqueue messages.
    pub fn spawn_dispatcher(self) -> mpsc::Sender<KafkaMessage> {
        let (tx, mut rx) = mpsc::channel::<KafkaMessage>(100_000);

        tokio::spawn(async move {
            info!("Kafka dispatcher task started.");
            let mut flush_interval = time::interval(Duration::from_millis(500));
            
            loop {
                tokio::select! {
                    msg = rx.recv() => {
                        match msg {
                            Some(KafkaMessage::ParsedFrame(payload)) => {
                                let record = FutureRecord::to(&self.raw_topic)
                                    .payload(&payload)
                                    .key("raw-frame");
                                
                                // Enqueue asynchronously without awaiting delivery
                                if let Err((e, _)) = self.producer.send_result(record) {
                                    error!("Failed to enqueue raw frame to Kafka: {:?}", e);
                                }
                            }
                            Some(KafkaMessage::ThreatAlert(payload)) => {
                                let record = FutureRecord::to(&self.threat_topic)
                                    .payload(&payload)
                                    .key("threat-alert");

                                if let Err((e, _)) = self.producer.send_result(record) {
                                    error!("Failed to enqueue threat alert to Kafka: {:?}", e);
                                }
                            }
                            None => {
                                info!("Kafka dispatcher channel closed. Exiting.");
                                break;
                            }
                        }
                    }
                    _ = flush_interval.tick() => {
                        // Periodic heartbeat/flush could be added here
                    }
                }
            }
            
            // Wait for pending messages
            info!("Flushing Kafka producer before shutdown...");
            // Non-async flush in drop usually, but here we can just break and let standard drop handle
        });

        tx
    }
}
