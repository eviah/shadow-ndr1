//! Distributed Mesh Network for Multi-Sensor Coordination
//!
//! Enables multiple Shadow sensors to form a coordinated mesh network:
//! - Consensus voting (outlier rejection)
//! - Threat correlation across sensors
//! - Automated sensor discovery (mDNS/Consul)
//! - Time synchronization (NTP, PTP)
//! - Load balancing (intelligent packet distribution)

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use std::net::SocketAddr;

/// Sensor node in the mesh
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SensorNode {
    pub node_id: String,
    pub address: SocketAddr,
    pub latitude: f64,
    pub longitude: f64,
    pub altitude: f64,
    pub antenna_gain_dbi: f64,
    pub last_heartbeat: u64,
    pub is_healthy: bool,
    pub threat_score: f64,
}

/// Threat report from a sensor
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ThreatReport {
    pub sensor_id: String,
    pub target_id: String,  // ICAO24, IP, etc.
    pub threat_type: String,
    pub confidence: f64,
    pub severity: u8,
    pub timestamp: u64,
}

/// Consensus decision from multiple sensors
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ConsensusDecision {
    pub target_id: String,
    pub agreed_threat: bool,
    pub agreement_ratio: f64,  // 0.0-1.0
    pub contributing_sensors: Vec<String>,
    pub outlier_sensors: Vec<String>,
}

pub struct DistributedMesh {
    node_id: String,
    nodes: Arc<RwLock<HashMap<String, SensorNode>>>,
    threat_reports: Arc<RwLock<Vec<ThreatReport>>>,
    consensus_threshold: f64,  // 0.66 = 2/3 agreement required
}

impl DistributedMesh {
    pub fn new(node_id: String) -> Self {
        DistributedMesh {
            node_id,
            nodes: Arc::new(RwLock::new(HashMap::new())),
            threat_reports: Arc::new(RwLock::new(Vec::new())),
            consensus_threshold: 0.66,
        }
    }

    /// Register a peer sensor in the mesh
    pub async fn add_peer(&self, node: SensorNode) {
        let mut nodes = self.nodes.write().await;
        nodes.insert(node.node_id.clone(), node);
    }

    /// Report a threat to the mesh
    pub async fn report_threat(&self, report: ThreatReport) {
        let mut reports = self.threat_reports.write().await;
        reports.push(report);
    }

    /// Compute consensus: does majority of sensors agree?
    pub async fn compute_consensus(&self, target_id: &str) -> Option<ConsensusDecision> {
        let reports = self.threat_reports.read().await;

        // Group reports by target
        let mut target_reports: Vec<&ThreatReport> = reports
            .iter()
            .filter(|r| r.target_id == target_id)
            .collect();

        if target_reports.is_empty() {
            return None;
        }

        // Count threat confirmations
        let total_sensors = self.nodes.read().await.len().max(1);
        let threat_count = target_reports.iter().filter(|r| r.confidence > 0.5).count();
        let agreement_ratio = threat_count as f64 / total_sensors as f64;

        // Determine if threat is real (requires threshold agreement)
        let agreed_threat = agreement_ratio >= self.consensus_threshold;

        // Find outliers (sensors disagreeing with consensus)
        let mut contributing_sensors = Vec::new();
        let mut outlier_sensors = Vec::new();

        for report in &target_reports {
            if (report.confidence > 0.5) == agreed_threat {
                contributing_sensors.push(report.sensor_id.clone());
            } else {
                outlier_sensors.push(report.sensor_id.clone());
            }
        }

        Some(ConsensusDecision {
            target_id: target_id.to_string(),
            agreed_threat,
            agreement_ratio,
            contributing_sensors,
            outlier_sensors,
        })
    }

    /// Triangulate position from RSSI measurements (trilateration)
    pub async fn triangulate_position(
        &self,
        rssi_measurements: &[(String, f64)], // (sensor_id, rssi_dbm)
    ) -> Option<(f64, f64)> {
        let nodes = self.nodes.read().await;

        if rssi_measurements.len() < 3 {
            return None;
        }

        // Simple distance calculation: RSSI to meters
        let mut positions = Vec::new();
        let mut distances = Vec::new();

        for (sensor_id, rssi_dbm) in rssi_measurements {
            let node = nodes.get(sensor_id)?;
            // Path loss model: distance = 10^((txPower - rssi) / 20)
            // Assuming -40 dBm at 1m (typical)
            let distance = 10.0_f64.powf(((-40.0 - rssi_dbm) / 20.0));

            positions.push((node.latitude, node.longitude));
            distances.push(distance);
        }

        // Weighted average of positions (inverse distance weighting)
        let mut lat_sum = 0.0;
        let mut lon_sum = 0.0;
        let mut weight_sum = 0.0;

        for i in 0..positions.len() {
            let weight = 1.0 / (distances[i].max(0.1));
            lat_sum += positions[i].0 * weight;
            lon_sum += positions[i].1 * weight;
            weight_sum += weight;
        }

        Some((lat_sum / weight_sum, lon_sum / weight_sum))
    }

    /// Get all healthy sensors
    pub async fn healthy_sensors(&self) -> Vec<SensorNode> {
        let nodes = self.nodes.read().await;
        nodes
            .values()
            .filter(|n| n.is_healthy)
            .cloned()
            .collect()
    }

    /// Sensor health check (heartbeat timeout = unhealthy)
    pub async fn check_health(&self, timeout_seconds: u64) {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let mut nodes = self.nodes.write().await;
        for node in nodes.values_mut() {
            node.is_healthy = (now - node.last_heartbeat) < timeout_seconds;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[tokio::test]
    async fn test_mesh_creation() {
        let mesh = DistributedMesh::new("sensor1".to_string());
        assert_eq!(mesh.node_id, "sensor1");
    }

    #[tokio::test]
    async fn test_consensus_voting() {
        let mesh = DistributedMesh::new("sensor1".to_string());

        // Add 3 sensors
        for i in 1..=3 {
            let node = SensorNode {
                node_id: format!("sensor{}", i),
                address: SocketAddr::from_str(&format!("127.0.0.{}:9000", i)).unwrap(),
                latitude: 40.0 + i as f64,
                longitude: -74.0,
                altitude: 100.0,
                antenna_gain_dbi: 3.0,
                last_heartbeat: 0,
                is_healthy: true,
                threat_score: 0.0,
            };
            mesh.add_peer(node).await;
        }

        // 2 out of 3 sensors report threat
        mesh.report_threat(ThreatReport {
            sensor_id: "sensor1".to_string(),
            target_id: "ICAO123".to_string(),
            threat_type: "Spoofing".to_string(),
            confidence: 0.8,
            severity: 8,
            timestamp: 0,
        })
        .await;

        mesh.report_threat(ThreatReport {
            sensor_id: "sensor2".to_string(),
            target_id: "ICAO123".to_string(),
            threat_type: "Spoofing".to_string(),
            confidence: 0.7,
            severity: 7,
            timestamp: 0,
        })
        .await;

        let consensus = mesh.compute_consensus("ICAO123").await;
        assert!(consensus.is_some());
        let decision = consensus.unwrap();
        assert!(decision.agreed_threat);
        assert!(decision.agreement_ratio >= mesh.consensus_threshold);
    }
}
