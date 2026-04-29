//! AI/ML Threat Intelligence Engine — Singularity Tier
//!
//! Combines per-flow statistical anomaly detection with two new capabilities:
//!
//! 1. **Recurrent Flow Fingerprinting (RFF)** — every analyzed flow is
//!    classified into an attack-stage label (recon → lateral → exfil) and
//!    appended to a per-source timeline. Whenever the timeline spells out the
//!    canonical kill-chain ordering inside a 5-minute window, a `KillChain`
//!    anomaly is emitted with a boosted confidence score.
//!
//! 2. **Bayesian Confidence Scoring (BCS)** — when several sensors observe
//!    the same flow, their `AnomalyScore`s are fused into a posterior using
//!    each sensor's calibrated prior + likelihood (replacing naive averaging).
//!
//! Backwards compatibility: the original `register_flow` / `analyze` API and
//! `AnomalyScore` shape are preserved so existing consumers keep working.

use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use tokio::sync::RwLock;
use serde::{Deserialize, Serialize};
use std::time::SystemTime;

const KILL_CHAIN_WINDOW_SECS: u64 = 300;
const KILL_CHAIN_HISTORY: usize = 32;
const ANOMALY_RING: usize = 10_000;

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
    pub score: f64,
    pub anomaly_type: String,
    pub deviation_magnitude: f64,
    pub confidence: f64,
    pub timestamp: u64,
}

/// Stage labels in the cyber kill chain.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum AttackStage {
    Recon,
    Lateral,
    Exfil,
    Other,
}

impl AttackStage {
    fn rank(self) -> i32 {
        match self {
            AttackStage::Recon => 0,
            AttackStage::Lateral => 1,
            AttackStage::Exfil => 2,
            AttackStage::Other => -1,
        }
    }
}

#[derive(Clone, Debug)]
struct StageEvent {
    stage: AttackStage,
    timestamp: u64,
}

/// Bayesian posterior produced by fusing multiple sensor verdicts.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BayesianConfidence {
    pub flow_id: String,
    pub posterior: f64,
    pub contributing_sensors: usize,
}

/// Per-sensor calibration (prior + true/false-positive rates).
#[derive(Clone, Debug)]
pub struct SensorCalibration {
    pub prior: f64,
    pub true_positive_rate: f64,
    pub false_positive_rate: f64,
}

impl Default for SensorCalibration {
    fn default() -> Self {
        SensorCalibration {
            prior: 0.05,
            true_positive_rate: 0.92,
            false_positive_rate: 0.07,
        }
    }
}

/// Singularity-tier ML engine.
pub struct AIThreatEngine {
    baselines: Arc<RwLock<HashMap<String, FlowFingerprint>>>,
    anomalies: Arc<RwLock<VecDeque<AnomalyScore>>>,
    normal_patterns: Arc<RwLock<HashMap<String, Vec<f64>>>>,
    /// Per-source timeline of attack-stage events (RFF state).
    stage_timelines: Arc<RwLock<HashMap<String, VecDeque<StageEvent>>>>,
    /// Per-sensor calibration used by Bayesian fusion.
    sensor_calibrations: Arc<RwLock<HashMap<String, SensorCalibration>>>,
    sensitivity: f64,
}

impl AIThreatEngine {
    pub fn new(sensitivity: f64) -> Self {
        AIThreatEngine {
            baselines: Arc::new(RwLock::new(HashMap::new())),
            anomalies: Arc::new(RwLock::new(VecDeque::with_capacity(ANOMALY_RING))),
            normal_patterns: Arc::new(RwLock::new(HashMap::new())),
            stage_timelines: Arc::new(RwLock::new(HashMap::new())),
            sensor_calibrations: Arc::new(RwLock::new(HashMap::new())),
            sensitivity: sensitivity.clamp(0.0, 1.0),
        }
    }

    pub async fn register_flow(&self, flow_id: String, fingerprint: FlowFingerprint) {
        let mut baselines = self.baselines.write().await;
        baselines.insert(flow_id, fingerprint);
    }

    /// Register/refresh a sensor's calibration profile.
    pub async fn register_sensor(&self, sensor_id: String, cal: SensorCalibration) {
        let mut s = self.sensor_calibrations.write().await;
        s.insert(sensor_id, cal);
    }

    /// Classify a fingerprint into an attack-stage label using fast heuristics.
    pub fn classify_stage(fp: &FlowFingerprint) -> AttackStage {
        // Recon: many tiny short-lived probes, low entropy.
        if fp.packet_size_avg < 120.0 && fp.inter_arrival_time_avg < 5.0 && fp.entropy < 4.0 {
            return AttackStage::Recon;
        }
        // Exfil: large payloads with high entropy (encrypted/compressed bulk).
        if fp.packet_size_avg > 800.0 && fp.entropy > 7.0 {
            return AttackStage::Exfil;
        }
        // Lateral: SMB/RPC-ish ports + medium payload with elevated flag churn.
        let lateral_ports = matches!(fp.port, 135 | 139 | 445 | 3389 | 5985 | 5986 | 22);
        if lateral_ports && fp.packet_size_avg > 200.0 && fp.packet_size_avg < 900.0 {
            return AttackStage::Lateral;
        }
        AttackStage::Other
    }

    fn now_secs() -> u64 {
        SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    }

    /// Append a stage observation and return Some(()) if the canonical
    /// recon → lateral → exfil chain has been observed within the window.
    async fn record_stage(&self, src_key: &str, stage: AttackStage) -> bool {
        if matches!(stage, AttackStage::Other) {
            return false;
        }
        let now = Self::now_secs();
        let mut timelines = self.stage_timelines.write().await;
        let timeline = timelines
            .entry(src_key.to_string())
            .or_insert_with(|| VecDeque::with_capacity(KILL_CHAIN_HISTORY));
        timeline.push_back(StageEvent { stage, timestamp: now });
        while timeline.len() > KILL_CHAIN_HISTORY {
            timeline.pop_front();
        }
        // Trim by age.
        while let Some(front) = timeline.front() {
            if now.saturating_sub(front.timestamp) > KILL_CHAIN_WINDOW_SECS {
                timeline.pop_front();
            } else {
                break;
            }
        }
        // Detect monotone subsequence covering ranks 0,1,2 in order.
        let mut highest = -1;
        let mut covered = [false; 3];
        for ev in timeline.iter() {
            let r = ev.stage.rank();
            if r >= highest {
                highest = r;
                if (0..=2).contains(&r) {
                    covered[r as usize] = true;
                }
            }
        }
        covered.iter().all(|&c| c)
    }

    /// Analyze packet for anomalies. Source IP timeline state is updated
    /// implicitly so kill-chain detections can fire on subsequent flows.
    pub async fn analyze(&self, flow_id: &str, fingerprint: &FlowFingerprint) -> Option<AnomalyScore> {
        let baseline_opt = {
            let baselines = self.baselines.read().await;
            baselines.get(flow_id).cloned()
        };
        let baseline = baseline_opt?;

        let size_z = (fingerprint.packet_size_avg - baseline.packet_size_avg).abs()
            / (baseline.packet_size_variance.sqrt() + 1e-8);
        let timing_z = (fingerprint.inter_arrival_time_avg - baseline.inter_arrival_time_avg).abs()
            / (baseline.inter_arrival_time_variance.sqrt() + 1e-8);
        let proto_changed = fingerprint.protocol_flags != baseline.protocol_flags;
        let entropy_delta = (fingerprint.entropy - baseline.entropy).abs();

        let mut anomaly_score = 0.0_f64;
        let mut anomaly_type = "Normal".to_string();

        if size_z > 3.0 {
            anomaly_score = (size_z / 10.0).min(1.0);
            anomaly_type = "SizeAnomaly".to_string();
        }
        if timing_z > 3.0 && (timing_z / 10.0) > anomaly_score {
            anomaly_score = (timing_z / 10.0).min(1.0);
            anomaly_type = "TimingAnomaly".to_string();
        }
        if proto_changed {
            anomaly_score = (anomaly_score + 0.5).min(1.0);
            anomaly_type = "ProtocolAnomaly".to_string();
        }
        if entropy_delta > 0.2 {
            anomaly_score = (anomaly_score + (entropy_delta * 0.5).min(0.4)).min(1.0);
            if anomaly_type == "Normal" {
                anomaly_type = "EntropyAnomaly".to_string();
            }
        }

        anomaly_score *= self.sensitivity;

        // Recurrent Flow Fingerprinting: append + look for kill chain.
        let stage = Self::classify_stage(fingerprint);
        let killed = self.record_stage(&fingerprint.src_addr, stage).await;
        if killed {
            anomaly_score = (anomaly_score + 0.55).min(1.0);
            anomaly_type = "KillChain".to_string();
        }

        if anomaly_score < 0.3 {
            return None;
        }

        let deviations = [size_z, timing_z, if proto_changed { 2.0 } else { 0.0 }, entropy_delta * 10.0];
        let score = AnomalyScore {
            flow_id: flow_id.to_string(),
            score: anomaly_score,
            anomaly_type,
            deviation_magnitude: deviations.iter().sum::<f64>() / deviations.len() as f64,
            confidence: (1.0 - (1.0 - anomaly_score).powi(2)).min(0.99),
            timestamp: Self::now_secs(),
        };

        let mut ring = self.anomalies.write().await;
        if ring.len() >= ANOMALY_RING {
            ring.pop_front();
        }
        ring.push_back(score.clone());

        Some(score)
    }

    /// Bayesian fusion of multiple sensor verdicts about the same flow.
    ///
    /// Each verdict is `(sensor_id, AnomalyScore)`. Sensors without a
    /// registered calibration use `SensorCalibration::default()`.
    pub async fn fuse_verdicts(
        &self,
        flow_id: &str,
        verdicts: &[(String, AnomalyScore)],
    ) -> BayesianConfidence {
        if verdicts.is_empty() {
            return BayesianConfidence {
                flow_id: flow_id.to_string(),
                posterior: 0.0,
                contributing_sensors: 0,
            };
        }
        let cals = self.sensor_calibrations.read().await;

        // Use the calibration of the first sensor as the seed prior.
        let seed_cal = cals
            .get(&verdicts[0].0)
            .cloned()
            .unwrap_or_default();
        let mut posterior = seed_cal.prior.clamp(1e-6, 1.0 - 1e-6);

        for (sensor_id, verdict) in verdicts {
            let cal = cals.get(sensor_id).cloned().unwrap_or_default();
            // Treat the verdict's score as the sensor's degree-of-belief.
            // Weight TPR/FPR by the verdict score so weak verdicts barely move
            // the posterior.
            let weight = verdict.score.clamp(0.0, 1.0);
            let tpr = cal.true_positive_rate.clamp(1e-3, 1.0 - 1e-3);
            let fpr = cal.false_positive_rate.clamp(1e-3, 1.0 - 1e-3);

            // Likelihood ratio shifts with verdict strength.
            let p_e_given_t = tpr.powf(weight) * (1.0 - tpr).powf(1.0 - weight);
            let p_e_given_f = fpr.powf(weight) * (1.0 - fpr).powf(1.0 - weight);

            let num = p_e_given_t * posterior;
            let den = num + p_e_given_f * (1.0 - posterior);
            posterior = if den > 1e-12 { num / den } else { posterior };
            posterior = posterior.clamp(1e-6, 1.0 - 1e-6);
        }

        BayesianConfidence {
            flow_id: flow_id.to_string(),
            posterior,
            contributing_sensors: verdicts.len(),
        }
    }

    pub async fn recent_anomalies(&self, seconds: u64) -> Vec<AnomalyScore> {
        let now = Self::now_secs();
        let anomalies = self.anomalies.read().await;
        anomalies
            .iter()
            .filter(|a| now.saturating_sub(a.timestamp) < seconds)
            .cloned()
            .collect()
    }

    pub async fn learn_pattern(&self, flow_id: String, values: Vec<f64>) {
        let mut patterns = self.normal_patterns.write().await;
        patterns.insert(flow_id, values);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fp(src: &str, port: u16, size: f64, iat: f64, entropy: f64) -> FlowFingerprint {
        FlowFingerprint {
            src_addr: src.to_string(),
            dst_addr: "10.0.0.1".to_string(),
            protocol: "TCP".to_string(),
            port,
            packet_size_avg: size,
            packet_size_variance: 50.0,
            inter_arrival_time_avg: iat,
            inter_arrival_time_variance: 1.0,
            protocol_flags: 0x02,
            entropy,
        }
    }

    #[tokio::test]
    async fn classify_stage_buckets() {
        assert_eq!(AIThreatEngine::classify_stage(&fp("a", 80, 60.0, 1.0, 2.0)), AttackStage::Recon);
        assert_eq!(AIThreatEngine::classify_stage(&fp("a", 445, 400.0, 5.0, 5.0)), AttackStage::Lateral);
        assert_eq!(AIThreatEngine::classify_stage(&fp("a", 443, 1200.0, 5.0, 7.5)), AttackStage::Exfil);
        assert_eq!(AIThreatEngine::classify_stage(&fp("a", 9999, 400.0, 5.0, 5.0)), AttackStage::Other);
    }

    #[tokio::test]
    async fn kill_chain_detected_in_order() {
        let engine = AIThreatEngine::new(1.0);
        let baseline = fp("attacker", 80, 60.0, 1.0, 2.0);
        engine.register_flow("recon".to_string(), baseline.clone()).await;
        engine.register_flow("lateral".to_string(), fp("attacker", 445, 400.0, 5.0, 5.0)).await;
        engine.register_flow("exfil".to_string(), fp("attacker", 443, 1200.0, 5.0, 7.5)).await;

        // Drive each through analyze with non-baseline values to trigger anomalies.
        let _ = engine.analyze("recon", &fp("attacker", 80, 60.0, 1.0, 2.0)).await;
        let _ = engine.analyze("lateral", &fp("attacker", 445, 400.0, 5.0, 5.0)).await;
        let res = engine.analyze("exfil", &fp("attacker", 443, 1200.0, 5.0, 7.5)).await;

        assert!(res.is_some(), "expected exfil stage to emit anomaly");
        let s = res.unwrap();
        assert_eq!(s.anomaly_type, "KillChain");
        assert!(s.score > 0.5);
    }

    #[tokio::test]
    async fn bayesian_fuses_verdicts() {
        let engine = AIThreatEngine::new(1.0);
        engine.register_sensor(
            "s1".to_string(),
            SensorCalibration { prior: 0.1, true_positive_rate: 0.95, false_positive_rate: 0.05 },
        )
        .await;
        engine.register_sensor(
            "s2".to_string(),
            SensorCalibration { prior: 0.1, true_positive_rate: 0.9, false_positive_rate: 0.08 },
        )
        .await;

        let verdict = |id: &str, score: f64| (id.to_string(), AnomalyScore {
            flow_id: "f".into(),
            score,
            anomaly_type: "x".into(),
            deviation_magnitude: 1.0,
            confidence: score,
            timestamp: 0,
        });

        let one = engine.fuse_verdicts("f", &[verdict("s1", 0.8)]).await;
        let two = engine.fuse_verdicts("f", &[verdict("s1", 0.8), verdict("s2", 0.8)]).await;

        assert!(two.posterior > one.posterior, "two agreeing sensors must raise posterior");
        assert_eq!(two.contributing_sensors, 2);
    }

    #[tokio::test]
    async fn baseline_close_traffic_is_clean() {
        let engine = AIThreatEngine::new(0.5);
        let baseline = FlowFingerprint {
            src_addr: "1.1.1.1".into(),
            dst_addr: "2.2.2.2".into(),
            protocol: "TCP".into(),
            port: 80,
            packet_size_avg: 500.0,
            packet_size_variance: 100.0,
            inter_arrival_time_avg: 10.0,
            inter_arrival_time_variance: 2.0,
            protocol_flags: 0x02,
            entropy: 5.5,
        };
        engine.register_flow("flow1".into(), baseline.clone()).await;
        let mut close = baseline.clone();
        close.packet_size_avg = 510.0;
        close.entropy = 5.4;
        let r = engine.analyze("flow1", &close).await;
        assert!(r.is_none() || r.unwrap().score < 0.3);
    }
}
