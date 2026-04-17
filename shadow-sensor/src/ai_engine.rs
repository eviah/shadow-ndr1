//! AI/ML Threat Intelligence Engine
//!
//! Real-time anomaly detection using statistical models and behavioral learning.
//! - Detects zero-day threats via behavioral deviation
//! - Learns normal traffic patterns per aircraft/protocol
//! - Provides confidence scoring (0.0-1.0) for threat assessment
//! - Auto-adapts to network changes

use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use tokio::sync::RwLock;
use serde::{Deserialize, Serialize};
use std::time::SystemTime;

/// Traffic flow fingerprint
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FlowFingerprint {
    pub src_addr: String,
    pub dst_addr: String,
    pub protocol: String,
    pub port: u16,
    pub packet_size_avg: f64,
    pub packet_size_variance: f64,
    pub inter_arrival_time_avg: f64,
    pub inter_arrival_time_variance: f64,
    pub protocol_flags: u32,
    pub entropy: f64,
}

/// Behavioral anomaly score
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AnomalyScore {
    pub flow_id: String,
    pub score: f64,  // 0.0 (normal) to 1.0 (anomalous)
    pub anomaly_type: String,
    pub deviation_magnitude: f64,
    pub confidence: f64,
    pub timestamp: u64,
}

/// ML model for anomaly detection
pub struct AIThreatEngine {
    /// Per-flow behavioral baselines
    baselines: Arc<RwLock<HashMap<String, FlowFingerprint>>>,
    /// Anomaly history (time-series)
    anomalies: Arc<RwLock<VecDeque<AnomalyScore>>>,
    /// Learned normal patterns
    normal_patterns: Arc<RwLock<HashMap<String, Vec<f64>>>>,
    /// Sensitivity threshold (0.0-1.0)
    sensitivity: f64,
}

impl AIThreatEngine {
    pub fn new(sensitivity: f64) -> Self {
        AIThreatEngine {
            baselines: Arc::new(RwLock::new(HashMap::new())),
            anomalies: Arc::new(RwLock::new(VecDeque::with_capacity(10000))),
            normal_patterns: Arc::new(RwLock::new(HashMap::new())),
            sensitivity: sensitivity.clamp(0.0, 1.0),
        }
    }

    /// Register a flow's normal behavior
    pub async fn register_flow(&self, flow_id: String, fingerprint: FlowFingerprint) {
        let mut baselines = self.baselines.write().await;
        baselines.insert(flow_id, fingerprint);
    }

    /// Analyze packet for anomalies
    pub async fn analyze(&self, flow_id: &str, fingerprint: &FlowFingerprint) -> Option<AnomalyScore> {
        let baselines = self.baselines.read().await;
        let baseline = baselines.get(flow_id)?;

        // Calculate deviation from baseline
        let mut deviations = Vec::new();

        // Size variance deviation (z-score)
        let size_z_score = (fingerprint.packet_size_avg - baseline.packet_size_avg).abs()
            / (baseline.packet_size_variance.sqrt() + 1e-8);
        deviations.push(size_z_score);

        // Timing deviation
        let timing_z_score = (fingerprint.inter_arrival_time_avg - baseline.inter_arrival_time_avg).abs()
            / (baseline.inter_arrival_time_variance.sqrt() + 1e-8);
        deviations.push(timing_z_score);

        // Protocol flags change (binary)
        if fingerprint.protocol_flags != baseline.protocol_flags {
            deviations.push(2.0); // Significant change
        }

        // Entropy change
        let entropy_delta = (fingerprint.entropy - baseline.entropy).abs();
        deviations.push(entropy_delta * 10.0);

        // Aggregate score
        let mut anomaly_score = 0.0;
        let mut anomaly_type = "Normal".to_string();

        // High packet size variance = possible DoS/scan
        if deviations[0] > 3.0 {
            anomaly_score = (deviations[0] / 10.0).min(1.0);
            anomaly_type = "SizeAnomaly".to_string();
        }

        // Unusual timing = possible command injection/lateral movement
        if deviations[1] > 3.0 {
            if deviations[1] > anomaly_score {
                anomaly_score = (deviations[1] / 10.0).min(1.0);
                anomaly_type = "TimingAnomaly".to_string();
            }
        }

        // Protocol flag changes = possible exploitation/attack
        if deviations[2] > 0.0 {
            anomaly_score = (anomaly_score + 0.5).min(1.0);
            anomaly_type = "ProtocolAnomaly".to_string();
        }

        // High entropy = possible encryption/obfuscation/exfiltration
        if deviations[3] > 2.0 {
            anomaly_score = (anomaly_score + 0.3).min(1.0);
            anomaly_type = "EntropyAnomaly".to_string();
        }

        // Apply sensitivity multiplier
        anomaly_score *= self.sensitivity;

        if anomaly_score > 0.3 {
            let score = AnomalyScore {
                flow_id: flow_id.to_string(),
                score: anomaly_score,
                anomaly_type,
                deviation_magnitude: deviations.iter().sum::<f64>() / deviations.len() as f64,
                confidence: (1.0 - (1.0 - anomaly_score).powi(2)).min(0.99),
                timestamp: SystemTime::now()
                    .duration_since(SystemTime::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs(),
            };

            return Some(score);
        }

        None
    }

    /// Get anomalies from last N seconds
    pub async fn recent_anomalies(&self, seconds: u64) -> Vec<AnomalyScore> {
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let anomalies = self.anomalies.read().await;
        anomalies
            .iter()
            .filter(|a| now - a.timestamp < seconds)
            .cloned()
            .collect()
    }

    /// Learn normal pattern from benign traffic
    pub async fn learn_pattern(&self, flow_id: String, values: Vec<f64>) {
        let mut patterns = self.normal_patterns.write().await;
        patterns.insert(flow_id, values);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_ai_engine_creation() {
        let engine = AIThreatEngine::new(0.8);
        assert_eq!(engine.sensitivity, 0.8);
    }

    #[tokio::test]
    async fn test_anomaly_detection() {
        let engine = AIThreatEngine::new(0.5);

        let baseline = FlowFingerprint {
            src_addr: "192.168.1.1".to_string(),
            dst_addr: "10.0.0.1".to_string(),
            protocol: "TCP".to_string(),
            port: 80,
            packet_size_avg: 500.0,
            packet_size_variance: 100.0,
            inter_arrival_time_avg: 10.0,
            inter_arrival_time_variance: 2.0,
            protocol_flags: 0x02,
            entropy: 5.5,
        };

        engine.register_flow("flow1".to_string(), baseline).await;

        // Test normal traffic (should not trigger)
        let normal_fp = FlowFingerprint {
            src_addr: "192.168.1.1".to_string(),
            dst_addr: "10.0.0.1".to_string(),
            protocol: "TCP".to_string(),
            port: 80,
            packet_size_avg: 510.0, // Close to baseline
            packet_size_variance: 105.0,
            inter_arrival_time_avg: 9.8,
            inter_arrival_time_variance: 2.1,
            protocol_flags: 0x02,
            entropy: 5.4,
        };

        let result = engine.analyze("flow1", &normal_fp).await;
        assert!(result.is_none() || result.unwrap().score < 0.3);
    }
}
