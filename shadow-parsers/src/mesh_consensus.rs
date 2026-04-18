//! Mesh Consensus Engine
//!
//! Coordinates position/identity reports across multiple sensor nodes.
//! Resolves conflicts and provides consensus ground truth.

use std::collections::HashMap;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SensorReport {
    pub sensor_id: String,
    pub timestamp_ms: u64,
    pub icao24: u32,
    pub lat: f64,
    pub lon: f64,
    pub altitude_ft: u32,
    pub speed_knots: f64,
    pub confidence: f32,
    pub rssi_dbm: Option<f32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConsensusSolution {
    pub icao24: u32,
    pub lat: f64,
    pub lon: f64,
    pub altitude_ft: u32,
    pub speed_knots: f64,
    pub sensor_count: u32,
    pub agreement_score: f32, // 0.0 = all disagree, 1.0 = perfect agreement
    pub outliers: Vec<String>, // sensor IDs that disagreed
}

pub struct MeshConsensus {
    pending_reports: HashMap<u32, Vec<SensorReport>>,
    solutions: Vec<ConsensusSolution>,
    config: ConsensusConfig,
}

#[derive(Debug, Clone)]
pub struct ConsensusConfig {
    /// Maximum time to wait for reports from other sensors (ms)
    pub max_wait_ms: u64,
    /// Required sensors for consensus (minimum)
    pub min_sensors: u32,
    /// Maximum position disagreement (nm) before flagging outlier
    pub max_position_disagreement_nm: f64,
    /// Maximum altitude disagreement (ft) before flagging outlier
    pub max_altitude_disagreement_ft: u32,
}

impl Default for ConsensusConfig {
    fn default() -> Self {
        ConsensusConfig {
            max_wait_ms: 2000,
            min_sensors: 2,
            max_position_disagreement_nm: 5.0,
            max_altitude_disagreement_ft: 500,
        }
    }
}

impl MeshConsensus {
    /// Create new mesh consensus engine
    pub fn new() -> Self {
        MeshConsensus {
            pending_reports: HashMap::new(),
            solutions: Vec::new(),
            config: ConsensusConfig::default(),
        }
    }

    /// Create with custom configuration
    pub fn with_config(config: ConsensusConfig) -> Self {
        MeshConsensus {
            pending_reports: HashMap::new(),
            solutions: Vec::new(),
            config,
        }
    }

    /// Add report from sensor
    pub fn add_report(&mut self, report: SensorReport) {
        self.pending_reports
            .entry(report.icao24)
            .or_insert_with(Vec::new)
            .push(report);
    }

    /// Compute consensus for all pending aircraft
    pub fn compute_consensus(&mut self) -> Vec<ConsensusSolution> {
        self.solutions.clear();

        for (icao24, reports) in &self.pending_reports {
            if reports.len() >= self.config.min_sensors as usize {
                if let Some(solution) = self.consensus_solution(*icao24, reports) {
                    self.solutions.push(solution);
                }
            }
        }

        self.pending_reports.clear();
        self.solutions.clone()
    }

    /// Compute consensus for single aircraft
    fn consensus_solution(&self, icao24: u32, reports: &[SensorReport]) -> Option<ConsensusSolution> {
        if reports.is_empty() {
            return None;
        }

        let mut positions = Vec::new();
        let mut altitudes = Vec::new();
        let mut speeds = Vec::new();
        let mut outlier_sensors = Vec::new();

        // Separate valid reports from outliers using consensus voting
        for report in reports {
            positions.push((report.lat, report.lon, report.sensor_id.clone()));
            altitudes.push((report.altitude_ft, report.sensor_id.clone()));
            speeds.push((report.speed_knots, report.sensor_id.clone()));
        }

        // Find outliers (reports that significantly disagree)
        let (median_lat, median_lon) = median_position(&positions);
        let median_alt = median_altitude(&altitudes);
        let median_speed = median_speed(&speeds);

        for report in reports {
            let dist = haversine_distance(median_lat, median_lon, report.lat, report.lon);
            let alt_diff = (report.altitude_ft as i32 - median_alt as i32).abs() as u32;
            let speed_diff = (report.speed_knots - median_speed).abs();

            if dist > self.config.max_position_disagreement_nm
                || alt_diff > self.config.max_altitude_disagreement_ft
                || speed_diff > 50.0
            {
                outlier_sensors.push(report.sensor_id.clone());
            }
        }

        let valid_count = (reports.len() as u32) - (outlier_sensors.len() as u32);
        let agreement_score = if reports.len() > 0 {
            (valid_count as f32) / (reports.len() as f32)
        } else {
            0.0
        };

        Some(ConsensusSolution {
            icao24,
            lat: median_lat,
            lon: median_lon,
            altitude_ft: median_alt,
            speed_knots: median_speed,
            sensor_count: reports.len() as u32,
            agreement_score,
            outliers: outlier_sensors,
        })
    }

    /// Get latest solutions
    pub fn get_solutions(&self) -> &[ConsensusSolution] {
        &self.solutions
    }

    /// Clear solutions
    pub fn clear(&mut self) {
        self.solutions.clear();
        self.pending_reports.clear();
    }
}

impl Default for MeshConsensus {
    fn default() -> Self {
        Self::new()
    }
}


/// Median position (lat/lon)
fn median_position(positions: &[(f64, f64, String)]) -> (f64, f64) {
    if positions.is_empty() {
        return (0.0, 0.0);
    }

    let mut lats: Vec<f64> = positions.iter().map(|(lat, _, _)| *lat).collect();
    let mut lons: Vec<f64> = positions.iter().map(|(_, lon, _)| *lon).collect();

    lats.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    lons.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));

    let mid = lats.len() / 2;
    let med_lat = if lats.len() % 2 == 0 {
        (lats[mid - 1] + lats[mid]) / 2.0
    } else {
        lats[mid]
    };

    let med_lon = if lons.len() % 2 == 0 {
        (lons[mid - 1] + lons[mid]) / 2.0
    } else {
        lons[mid]
    };

    (med_lat, med_lon)
}

/// Median altitude
fn median_altitude(altitudes: &[(u32, String)]) -> u32 {
    if altitudes.is_empty() {
        return 0;
    }

    let mut alts: Vec<u32> = altitudes.iter().map(|(alt, _)| *alt).collect();
    alts.sort();

    let mid = alts.len() / 2;
    if alts.len() % 2 == 0 {
        ((alts[mid - 1] + alts[mid]) / 2) as u32
    } else {
        alts[mid]
    }
}

/// Median speed
fn median_speed(speeds: &[(f64, String)]) -> f64 {
    if speeds.is_empty() {
        return 0.0;
    }

    let mut spds: Vec<f64> = speeds.iter().map(|(spd, _)| *spd).collect();
    spds.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));

    let mid = spds.len() / 2;
    if spds.len() % 2 == 0 {
        (spds[mid - 1] + spds[mid]) / 2.0
    } else {
        spds[mid]
    }
}

/// Haversine distance (nm)
fn haversine_distance(lat1: f64, lon1: f64, lat2: f64, lon2: f64) -> f64 {
    const EARTH_RADIUS_NM: f64 = 3440.07;

    let lat1_rad = lat1.to_radians();
    let lat2_rad = lat2.to_radians();
    let delta_lat = (lat2 - lat1).to_radians();
    let delta_lon = (lon2 - lon1).to_radians();

    let a = (delta_lat / 2.0).sin().powi(2)
        + lat1_rad.cos() * lat2_rad.cos() * (delta_lon / 2.0).sin().powi(2);
    let c = 2.0 * a.sqrt().atan2((1.0 - a).sqrt());

    EARTH_RADIUS_NM * c
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_consensus() {
        let mut consensus = MeshConsensus::new();

        // Add reports from 3 sensors (all agreeing)
        for i in 0..3 {
            consensus.add_report(SensorReport {
                sensor_id: format!("SENSOR_{}", i),
                timestamp_ms: 1000,
                icao24: 0x123456,
                lat: 40.0 + (i as f64) * 0.01, // Slight variation
                lon: -73.0,
                altitude_ft: 35000,
                speed_knots: 450.0,
                confidence: 0.95,
                rssi_dbm: Some(-50.0),
            });
        }

        let solutions = consensus.compute_consensus();
        assert_eq!(solutions.len(), 1);
        assert!(solutions[0].agreement_score > 0.9);
    }
}
