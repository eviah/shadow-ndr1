//! Burst & Spoofing Detection Engine
//!
//! Detects sudden aircraft appearances (no gradual position trail),
//! aircraft teleportation, and anomalous behavior patterns.

use std::collections::HashMap;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AircraftTrack {
    pub icao24: u32,
    pub callsign: String,
    pub first_seen: u64,
    pub last_seen: u64,
    pub position_history: Vec<(u64, f64, f64)>, // (timestamp_ms, lat, lon)
    pub altitude_history: Vec<(u64, u32)>,       // (timestamp_ms, altitude_ft)
    pub interaction_count: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum BurstIndicator {
    /// Aircraft appears without position history (classic spoofing)
    SuddenAppearance { first_seen: u64 },
    /// Aircraft position jumped > distance_nm in < time_ms
    Teleportation { distance_nm: f64, time_ms: u64 },
    /// Altitude change > rate_fpm/sec
    ImpossibleAltitudeChange { rate_fpm: f64 },
    /// Aircraft vanishes and reappears elsewhere
    DisappearanceReappearance { gap_ms: u64, distance_nm: f64 },
    /// Position noise too high (>aircraft_turn_rate)
    ExcessivePositionJitter { variance: f64 },
    /// Aircraft with multiple identities (callsign changes)
    CallsignSpoofing { callsigns: Vec<String> },
}

pub struct BurstDetector {
    tracks: HashMap<u32, AircraftTrack>,
    detections: Vec<(u32, BurstIndicator)>,
    config: BurstConfig,
}

#[derive(Debug, Clone)]
pub struct BurstConfig {
    /// Minimum position reports before aircraft is considered "established"
    pub min_history_length: u32,
    /// Maximum reasonable speed (knots) for civilian aircraft
    pub max_speed_knots: f64,
    /// Maximum altitude rate (fpm/sec)
    pub max_altitude_rate: f64,
    /// Timeout after which aircraft is considered disappeared (ms)
    pub disappearance_timeout_ms: u64,
    /// Maximum reasonable jitter (nm)
    pub max_position_jitter_nm: f64,
}

impl Default for BurstConfig {
    fn default() -> Self {
        BurstConfig {
            min_history_length: 3,
            max_speed_knots: 550.0,  // Mach 0.85 @ cruise
            max_altitude_rate: 6000.0,  // 6000 fpm/sec
            disappearance_timeout_ms: 5000,
            max_position_jitter_nm: 0.5,
        }
    }
}

impl BurstDetector {
    /// Create new burst detector
    pub fn new() -> Self {
        BurstDetector {
            tracks: HashMap::new(),
            detections: Vec::new(),
            config: BurstConfig::default(),
        }
    }

    /// Create with custom configuration
    pub fn with_config(config: BurstConfig) -> Self {
        BurstDetector {
            tracks: HashMap::new(),
            detections: Vec::new(),
            config,
        }
    }

    /// Process position update
    pub fn update(&mut self, icao24: u32, callsign: &str, timestamp_ms: u64, lat: f64, lon: f64, altitude_ft: u32) {
        let track = self.tracks.entry(icao24).or_insert_with(|| AircraftTrack {
            icao24,
            callsign: callsign.to_string(),
            first_seen: timestamp_ms,
            last_seen: timestamp_ms,
            position_history: Vec::new(),
            altitude_history: Vec::new(),
            interaction_count: 0,
        });

        track.last_seen = timestamp_ms;
        track.interaction_count += 1;

        // Check for anomalies
        if track.position_history.len() >= self.config.min_history_length as usize {
            // Teleportation check
            if let Some((prev_time, prev_lat, prev_lon)) = track.position_history.last() {
                let distance_nm = haversine_distance(*prev_lat, *prev_lon, lat, lon);
                let time_delta_ms = timestamp_ms - prev_time;
                let time_delta_sec = (time_delta_ms as f64) / 1000.0;
                let speed_knots = (distance_nm / time_delta_sec) * 3600.0; // nm/hr

                if speed_knots > self.config.max_speed_knots {
                    self.detections.push((
                        icao24,
                        BurstIndicator::Teleportation {
                            distance_nm,
                            time_ms: time_delta_ms,
                        },
                    ));
                }
            }
        } else if track.position_history.is_empty() {
            // First report - check if it's a sudden appearance (no gradual trail)
            self.detections.push((
                icao24,
                BurstIndicator::SuddenAppearance {
                    first_seen: timestamp_ms,
                },
            ));
        }

        // Altitude rate check
        if let Some((prev_time, prev_alt)) = track.altitude_history.last() {
            let alt_delta_ft = (altitude_ft as i32 - *prev_alt as i32).abs() as f64;
            let time_delta_sec = (timestamp_ms - prev_time) as f64 / 1000.0;
            let alt_rate = alt_delta_ft / time_delta_sec;

            if alt_rate > self.config.max_altitude_rate {
                self.detections.push((
                    icao24,
                    BurstIndicator::ImpossibleAltitudeChange {
                        rate_fpm: alt_rate,
                    },
                ));
            }
        }

        // Callsign consistency check
        if track.callsign != callsign && !callsign.is_empty() {
            let mut callsigns = vec![track.callsign.clone(), callsign.to_string()];
            callsigns.sort();
            callsigns.dedup();

            if callsigns.len() > 1 {
                self.detections.push((
                    icao24,
                    BurstIndicator::CallsignSpoofing {
                        callsigns,
                    },
                ));
            }
            track.callsign = callsign.to_string();
        }

        track.position_history.push((timestamp_ms, lat, lon));
        track.altitude_history.push((timestamp_ms, altitude_ft));

        // Keep history bounded to last 1000 reports
        if track.position_history.len() > 1000 {
            track.position_history.remove(0);
        }
        if track.altitude_history.len() > 1000 {
            track.altitude_history.remove(0);
        }
    }

    /// Get all detections and clear
    pub fn get_detections(&mut self) -> Vec<(u32, BurstIndicator)> {
        std::mem::take(&mut self.detections)
    }

    /// Get aircraft track
    pub fn get_track(&self, icao24: u32) -> Option<&AircraftTrack> {
        self.tracks.get(&icao24)
    }

    /// Get all tracks
    pub fn get_all_tracks(&self) -> Vec<&AircraftTrack> {
        self.tracks.values().collect()
    }

    /// Clean up disappeared aircraft
    pub fn cleanup(&mut self, current_time_ms: u64) {
        self.tracks.retain(|_, track| {
            current_time_ms - track.last_seen < self.config.disappearance_timeout_ms
        });
    }
}

impl Default for BurstDetector {
    fn default() -> Self {
        Self::new()
    }
}

/// Haversine distance calculation (lat/lon to nautical miles)
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
    fn test_haversine_distance() {
        // Test distance between JFK (40.6413, -73.7781) and LHR (51.4700, -0.4543)
        let dist = haversine_distance(40.6413, -73.7781, 51.4700, -0.4543);
        // Should be ~3450 nm
        assert!((dist - 3450.0).abs() < 100.0);
    }

    #[test]
    fn test_sudden_appearance_detection() {
        let mut detector = BurstDetector::new();
        detector.update(0x123456, "BA9", 1000, 40.0, -73.0, 35000);

        let detections = detector.get_detections();
        assert!(detections.iter().any(|(_, ind)| matches!(ind, BurstIndicator::SuddenAppearance { .. })));
    }

    #[test]
    fn test_teleportation_detection() {
        let mut detector = BurstDetector::new();

        // First position
        detector.update(0x123456, "BA9", 1000, 40.0, -73.0, 35000);
        detector.get_detections(); // Clear

        // Jump to Africa (unrealistic speed)
        detector.update(0x123456, "BA9", 1100, 0.0, 20.0, 35000);

        let detections = detector.get_detections();
        assert!(detections.iter().any(|(_, ind)| matches!(ind, BurstIndicator::Teleportation { .. })));
    }
}
