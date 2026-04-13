use anyhow::{Context, Result};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::watch;
use tracing::{info, warn, error, debug};
use crossbeam_channel::{bounded, Receiver};

use crate::config::AppConfig;
use crate::processor::PacketProcessor;

pub struct CaptureEngine {
    config: AppConfig,
    processor: Arc<PacketProcessor>,
    shutdown_tx: watch::Sender<bool>,
    shutdown_rx: watch::Receiver<bool>,
    stats: Arc<tokio::sync::Mutex<CaptureStats>>,
}

#[derive(Default)]
struct CaptureStats {
    packets_captured: u64,
    packets_dropped_rate_limit: u64,
    packets_dropped_backpressure: u64,
    batches_created: u64,
}

impl CaptureEngine {
    pub async fn new(config: AppConfig, processor: Arc<PacketProcessor>) -> Result<Self> {
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        Ok(Self {
            config,
            processor,
            shutdown_tx,
            shutdown_rx,
            stats: Arc::new(tokio::sync::Mutex::new(CaptureStats::default())),
        })
    }

    pub async fn run(&mut self) -> Result<()> {
        if self.config.enable_af_xdp {
            #[cfg(feature = "af_xdp")]
            return self.run_af_xdp().await;
            #[cfg(not(feature = "af_xdp"))]
            anyhow::bail!("AF_XDP feature not enabled");
        } else {
            self.run_pcap().await
        }
    }

    pub async fn stop(&mut self) -> Result<()> {
        let _ = self.shutdown_tx.send(true);
        Ok(())
    }

    async fn run_pcap(&mut self) -> Result<()> {
        use pcap::{Capture, Device};
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::sync::Arc as StdArc;

        let devices = Device::list().context("Failed to list pcap devices")?;
        info!("Available pcap interfaces:");
        for dev in &devices {
            info!("  {} (desc: {:?})", dev.name, dev.desc);
        }

        let interfaces_to_use: Vec<String> = if self.config.interfaces.is_empty() {
            devices.iter().map(|d| d.name.clone()).collect()
        } else {
            self.config.interfaces.clone()
        };

        if interfaces_to_use.is_empty() {
            warn!("No interfaces specified or found, capture will not start");
            return Ok(());
        }

        let bpf_filter = self.config.bpf_filter.clone();
        let promisc = self.config.promisc;
        let snaplen = self.config.snaplen;
        let rate_limit_pps = self.config.rate_limit_pps;

        let rate_interval = if rate_limit_pps > 0 {
            Some(Duration::from_secs(1) / rate_limit_pps)
        } else {
            None
        };

        let (packet_tx, packet_rx) = bounded::<Vec<u8>>(100_000);

        let batcher_config = self.config.clone();
        let batcher_processor = self.processor.clone();
        let batcher_stats = self.stats.clone();
        let batcher_shutdown_rx = self.shutdown_rx.clone();
        let batcher_handle = tokio::spawn(async move {
            Self::run_batcher(
                packet_rx,
                batcher_processor,
                batcher_config,
                batcher_stats,
                batcher_shutdown_rx,
            ).await;
        });

        let mut capture_handles = Vec::new();
        let running = StdArc::new(AtomicBool::new(true));
        let shutdown_flag = running.clone();

        for iface in interfaces_to_use {
            let device = devices.iter().find(|d| d.name == iface);
            let cap = match device {
                Some(dev) => {
                    debug!("Opening device: {}", dev.name);
                    // Try to open with minimal timeout first
                    let cap_builder = Capture::from_device(dev.clone())
                        .context(format!("Failed to open device {}", dev.name))?;
                    
                    // Apply settings carefully - don't use immediate_mode on Windows with pcap
                    let cap = cap_builder
                        .promisc(promisc)
                        .snaplen(snaplen)
                        .timeout(100)  // Reduce timeout to 100ms for quicker polling
                        .open()
                        .context(format!("Failed to capture on {}", dev.name))?;
                    
                    info!("Successfully opened interface: {} (desc: {:?})", dev.name, dev.desc);
                    cap
                }
                None => {
                    warn!("Interface '{}' not found, skipping", iface);
                    continue;
                }
            };

            let mut cap = cap;
            
            // Apply filter AFTER opening, not before
            if let Some(ref filter) = bpf_filter {
                if !filter.is_empty() {
                    info!("Attempting to set BPF filter on {}: '{}'", iface, filter);
                    match cap.filter(filter, true) {
                        Ok(_) => {
                            info!("✅ Applied BPF filter: {}", filter);
                        }
                        Err(e) => {
                            warn!("⚠️  Failed to set BPF filter: {}, continuing without filter", e);
                            // Continue without filter - don't fail
                        }
                    }
                }
            } else {
                info!("No BPF filter specified, capturing all packets");
            }

            let packet_tx_clone = packet_tx.clone();
            let rate_interval_clone = rate_interval;
            let shutdown_flag_clone = shutdown_flag.clone();
            let iface_name = iface.clone();

            let handle = tokio::task::spawn_blocking(move || {
                let mut last_rate_check = Instant::now();
                let mut packets_this_second = 0;
                let mut consecutive_timeouts = 0;
                
                info!("Capture thread started for {}", iface_name);
                
                while shutdown_flag_clone.load(Ordering::Relaxed) {
                    match cap.next_packet() {
                        Ok(pkt) => {
                            consecutive_timeouts = 0;  // Reset timeout counter on successful packet
                            debug!("✅ Captured packet on {} - {} bytes", iface_name, pkt.data.len());
                            
                            if let Some(_interval) = rate_interval_clone {
                                packets_this_second += 1;
                                let elapsed = last_rate_check.elapsed();
                                if elapsed >= Duration::from_secs(1) {
                                    last_rate_check = Instant::now();
                                    packets_this_second = 0;
                                } else if packets_this_second > rate_limit_pps as usize {
                                    continue;
                                }
                            }
                            let data = pkt.data.to_vec();
                            if let Err(e) = packet_tx_clone.try_send(data) {
                                warn!("Packet dropped on {} due to backpressure: {}", iface_name, e);
                            }
                        }
                        Err(e) => {
                            let err_str = e.to_string();
                            // Timeout is normal when no packets - don't break the loop
                            if err_str.contains("timeout") || err_str.contains("EAGAIN") || err_str.contains("Timeout") {
                                consecutive_timeouts += 1;
                                if consecutive_timeouts % 50 == 0 {
                                    debug!("Timeouts on {}: {} consecutive (no packets yet)", iface_name, consecutive_timeouts);
                                }
                                // No sleep needed - timeout already provides the delay
                                continue;
                            } else {
                                error!("Capture error on {}: {}", iface_name, e);
                                break;
                            }
                        }
                    }
                }
                info!("Capture stopped on {}", iface_name);
            });
            capture_handles.push(handle);
        }

        if capture_handles.is_empty() {
            error!("No valid interfaces could be opened. Exiting.");
            return Ok(());
        }

        info!("✅ Capture engine running on {} interface(s)", capture_handles.len());

        self.shutdown_rx.changed().await.ok();
        info!("Shutdown signal received, stopping captures...");

        running.store(false, Ordering::Relaxed);

        for handle in capture_handles {
            let _ = handle.await;
        }

        drop(packet_tx);
        batcher_handle.await.ok();

        let stats = self.stats.lock().await;
        info!(
            "Capture stats: captured={}, dropped_rate={}, dropped_backpressure={}, batches={}",
            stats.packets_captured,
            stats.packets_dropped_rate_limit,
            stats.packets_dropped_backpressure,
            stats.batches_created
        );

        Ok(())
    }

    async fn run_batcher(
        packet_rx: Receiver<Vec<u8>>,
        processor: Arc<PacketProcessor>,
        config: AppConfig,
        stats: Arc<tokio::sync::Mutex<CaptureStats>>,
        shutdown_rx: watch::Receiver<bool>,
    ) {
        let mut batch = Vec::with_capacity(config.batch_size);
        let mut last_flush = Instant::now();
        let flush_interval = Duration::from_millis(config.batch_flush_interval_ms);
        let dynamic = config.dynamic_batching_enabled;

        loop {
            let timeout = flush_interval.saturating_sub(last_flush.elapsed());
            let recv_result: Result<Option<Vec<u8>>, crossbeam_channel::RecvTimeoutError> = if timeout > Duration::ZERO {
                match packet_rx.recv_timeout(timeout) {
                    Ok(data) => Ok(Some(data)),
                    Err(crossbeam_channel::RecvTimeoutError::Timeout) => Ok(None),
                    Err(crossbeam_channel::RecvTimeoutError::Disconnected) => break,
                }
            } else {
                Ok(None)
            };

            match recv_result {
                Ok(Some(data)) => {
                    batch.push(data);
                    let target_size = if dynamic {
                        let load_factor = processor.get_load_factor().await;
                        (config.batch_size as f64 * load_factor).ceil() as usize
                    } else {
                        config.batch_size
                    };
                    if batch.len() >= target_size {
                        let batch_to_send = std::mem::take(&mut batch);
                        let batch_len = batch_to_send.len();
                        let p = processor.clone();
                        tokio::spawn(async move {
                            p.process_batch(batch_to_send).await;
                        });
                        {
                            let mut s = stats.lock().await;
                            s.batches_created += 1;
                            s.packets_captured += batch_len as u64;
                        }
                        last_flush = Instant::now();
                    }
                }
                Ok(None) => {
                    if !batch.is_empty() {
                        let batch_to_send = std::mem::take(&mut batch);
                        let batch_len = batch_to_send.len();
                        let p = processor.clone();
                        tokio::spawn(async move {
                            p.process_batch(batch_to_send).await;
                        });
                        {
                            let mut s = stats.lock().await;
                            s.batches_created += 1;
                            s.packets_captured += batch_len as u64;
                        }
                        last_flush = Instant::now();
                    }
                }
                Err(e) => {
                    warn!("Packet receiver channel closed: {}", e);
                    break;
                }
            }

            if *shutdown_rx.borrow() {
                break;
            }
        }

        if !batch.is_empty() {
            processor.process_batch(batch).await;
        }
        info!("Batcher finished");
    }

    #[cfg(feature = "af_xdp")]
    async fn run_af_xdp(&self) -> Result<()> {
        use af_xdp::{Socket, Config as XdpConfig, Umem, UmemBuilder};
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::sync::Arc as StdArc;

        let (packet_tx, packet_rx) = bounded::<Vec<u8>>(100_000);
        let batcher_config = self.config.clone();
        let batcher_processor = self.processor.clone();
        let batcher_stats = self.stats.clone();
        let batcher_shutdown_rx = self.shutdown_rx.clone();
        let batcher_handle = tokio::spawn(async move {
            Self::run_batcher(packet_rx, batcher_processor, batcher_config, batcher_stats, batcher_shutdown_rx).await;
        });

        let mut handles = Vec::new();
        let running = StdArc::new(AtomicBool::new(true));
        let shutdown_flag = running.clone();

        for iface in &self.config.interfaces {
            let umem = UmemBuilder::new().build()?;
            let config = XdpConfig::default();
            let mut socket = Socket::new(&config, umem, iface)?;
            let packet_tx_clone = packet_tx.clone();
            let iface_name = iface.clone();
            let shutdown_flag_clone = shutdown_flag.clone();
            let rate_limit_pps = self.config.rate_limit_pps;

            let handle = tokio::task::spawn_blocking(move || {
                let mut last_rate_check = Instant::now();
                let mut packets_this_second = 0;
                while shutdown_flag_clone.load(Ordering::Relaxed) {
                    match socket.recv() {
                        Ok(frame) => {
                            if rate_limit_pps > 0 {
                                packets_this_second += 1;
                                let elapsed = last_rate_check.elapsed();
                                if elapsed >= Duration::from_secs(1) {
                                    last_rate_check = Instant::now();
                                    packets_this_second = 0;
                                } else if packets_this_second > rate_limit_pps as usize {
                                    continue;
                                }
                            }
                            let _ = packet_tx_clone.try_send(frame.data.to_vec());
                        }
                        Err(e) => {
                            warn!("AF_XDP error on {}: {}", iface_name, e);
                            break;
                        }
                    }
                }
                info!("AF_XDP capture stopped on {}", iface_name);
            });
            handles.push(handle);
        }

        info!("✅ AF_XDP capture engine running on {} interface(s)", handles.len());

        self.shutdown_rx.changed().await.ok();
        running.store(false, Ordering::Relaxed);

        for h in handles {
            let _ = h.await;
        }
        drop(packet_tx);
        batcher_handle.await.ok();

        Ok(())
    }

    pub fn start_health_server(&self, port: u16) -> Result<tokio::task::JoinHandle<()>> {
        use axum::{routing::get, Json, Router};
        use std::net::SocketAddr;
        let processor = self.processor.clone();
        let stats = self.stats.clone();
        let app = Router::new()
            .route("/health", get(move || {
                let p = processor.clone();
                let s = stats.clone();
                async move {
                    let stats = p.stats().await;
                    let capture_stats = s.lock().await;
                    let response = serde_json::json!({
                        "processor": stats,
                        "capture": {
                            "packets_captured": capture_stats.packets_captured,
                            "dropped_rate_limit": capture_stats.packets_dropped_rate_limit,
                            "dropped_backpressure": capture_stats.packets_dropped_backpressure,
                            "batches_created": capture_stats.batches_created,
                        }
                    });
                    Json(response)
                }
            }));
        let addr = SocketAddr::from(([0,0,0,0], port));
        let handle = tokio::spawn(async move {
            let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
            axum::serve(listener, app).await.unwrap();
        });
        Ok(handle)
    }
}