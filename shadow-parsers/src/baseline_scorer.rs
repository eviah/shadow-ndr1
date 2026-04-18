//! Baseline Flight Profile Scorer
//!
//! Builds and maintains baseline flight profiles for each aircraft.
//! Scores deviation from baseline behavior to detect anomalies.

use std::collections::HashMap;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FlightProfile {
    pub icao24: u32,
    pub callsign: String,
    pub samples: u32,
    pub avg_latitude: f64,
    pub avg_longitude: f64,
    pub avg_altitude_ft: u32,
    pub avg_speed_knots: f64,
    pub avg_vertical_rate_fpm: f64,
    pub typical_routes: Vec<String>,
    pub operating_hours: (u8, u8), // (start_hour, end_hour) UTC
    pub confidence: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BaselineDeviation {
    pub icao24: u32,
    pub metric: String,
    pub expected: f64,
    pub observed: f64,
    pub deviation_percent: f64,
    pub risk_score: f32, // 0.0 = normal, 1.0 = highly anomalous
}

pub struct BaselineScorer {
    profiles: HashMap<u32, FlightProfile>,
    deviations: Vec<BaselineDeviation>,
    config: ScorerConfig,
}

#[derive(Debug, Clone)]
pub struct ScorerConfig {
    /// Minimum samples before baseline is considered reliable
    pub min_samples_for_baseline: u32,
    /// Acceptable deviation range (%)
    pub altitude_deviation_threshold: f64,
    pub speed_deviation_threshold: f64,
    pub location_deviation_threshold: f64, // nm
    /// Learning rate for baseline updates (0.0-1.0)
    pub learning_rate: f64,
}

impl Default for ScorerConfig {
    fn default() -> Self {
        ScorerConfig {
            min_samples_for_baseline: 10,
            altitude_deviation_threshold: 15.0,     // 15% deviation
            speed_deviation_threshold: 20.0,         // 20% deviation
            location_deviation_threshold: 50.0,      // 50 nm deviation
            learning_rate: 0.05,
        }
    }
}

impl BaselineScorer {
    /// Create new baseline scorer
    pub fn new() -> Self {
        BaselineScorer {
            profiles: HashMap::new(),
            deviations: Vec::new(),
            config: ScorerConfig::default(),
        }
    }

    /// Create with custom configuration
    pub fn with_config(config: ScorerConfig) -> Self {
        BaselineScorer {
            profiles: HashMap::new(),
            deviations: Vec::new(),
            config,
        }
    }

    /// Update baseline with new observation
    pub fn observe(&mut self, icao24: u32, callsign: &str, lat: f64, lon: f64, altitude_ft: u32, speed_knots: f64) {
        let profile = self.profiles.entry(icao24).or_insert_with(|| FlightProfile {
            icao24,
            callsign: callsign.to_string(),
            samples: 0,
            avg_latitude: lat,
            avg_longitude: lon,
            avg_altitude_ft: altitude_ft,
            avg_speed_knots: speed_knots,
            avg_vertical_rate_fpm: 0.0,
            typical_routes: Vec::new(),
            operating_hours: (0, 24),
            confidence: 0.0,
        });

        // Update running averages (exponential moving average)
        let lr = self.config.learning_rate;
        profile.avg_latitude = profile.avg_latitude * (1.0 - lr) + lat * lr;
        profile.avg_longitude = profile.avg_longitude * (1.0 - lr) + lon * lr;
        profile.avg_altitude_ft = ((profile.avg_altitude_ft as f64) * (1.0 - lr) + (altitude_ft as f64) * lr) as u32;
        profile.avg_speed_knots = profile.avg_speed_knots * (1.0 - lr) + speed_knots * lr;

        profile.samples += 1;
        profile.confidence = ((profile.samples as f32 / self.config.min_samples_for_baseline as f32).min(1.0)) * 0.9 + 0.1;
    }

    /// Score deviation from baseline
    pub fn score_deviation(&mut self, icao24: u32, lat: f64, lon: f64, altitude_ft: u32, speed_knots: f64) -> f32 {
        if let Some(profile) = self.profiles.get(&icao24) {
            if profile.samples < self.config.min_samples_for_baseline {
                return 0.0; // Not enough baseline data
            }

            let mut total_risk = 0.0;
            let mut factors = 0;

            // Altitude deviation
            let alt_deviation = ((altitude_ft as f64 - profile.avg_altitude_ft as f64).abs() / profile.avg_altitude_ft as f64) * 100.0;
            if alt_deviation > self.config.altitude_deviation_threshold {
                let dev = BaselineDeviation {
                    icao24,
                    metric: "altitude_ft".to_string(),
                    expected: profile.avg_altitude_ft as f64,
                    observed: altitude_ft as f64,
                    deviation_percent: alt_deviation,
                    risk_score: ((alt_deviation / 100.0).min(1.0)) as f32,
                };
                total_risk += dev.risk_score as f64;
                factors += 1;
                self.deviations.push(dev);
            }

            // Speed deviation
            let speed_deviation = ((speed_knots - profile.avg_speed_knots).abs() / profile.avg_speed_knots) * 100.0;
            if speed_deviation > self.config.speed_deviation_threshold {
                let dev = BaselineDeviation {
                    icao24,
                    metric: "speed_knots".to_string(),
                    expected: profile.avg_speed_knots,
                    observed: speed_knots,
                    deviation_percent: speed_deviation,
                    risk_score: ((speed_deviation / 100.0).min(1.0)) as f32,
                };
                total_risk += dev.risk_score as f64;
                factors += 1;
                self.deviations.push(dev);
            }

            // Location deviation
            let loc_deviation = haversine_distance(profile.avg_latitude, profile.avg_longitude, lat, lon);
            if loc_deviation > self.config.location_deviation_threshold {
                let dev = BaselineDeviation {
                    icao24,
                    metric: "location_nm".to_string(),
                    expected: 0.0,
                    observed: loc_deviation,
                    deviation_percent: (loc_deviation / self.config.location_deviation_threshold) * 100.0,
                    risk_score: ((loc_deviation / (self.config.location_deviation_threshold * 10.0)).min(1.0)) as f32,
                };
                total_risk += dev.risk_score as f64;
                factors += 1;
                self.deviations.push(dev);
            }

            if factors > 0 {
                (total_risk / factors as f64) as f32
            } else {
                0.0
            }
        } else {
            0.0 // No baseline yet
        }
    }

    /// Get all recent deviations and clear
    pub fn get_deviations(&mut self) -> Vec<BaselineDeviation> {
        std::mem::take(&mut self.deviations)
    }

    /// Get profile for aircraft
    pub fn get_profile(&self, icao24: u32) -> Option<&FlightProfile> {
        self.profiles.get(&icao24)
    }

    /// Get all profiles
    pub fn get_all_profiles(&self) -> Vec<&FlightProfile> {
        self.profiles.values().collect()
    }

    /// Get statistics
    pub fn get_stats(&self) -> (u32, u32) {
        let total_profiles = self.profiles.len() as u32;
        let confident_profiles = self.profiles.values().filter(|p| p.confidence > 0.8).count() as u32;
        (total_profiles, confident_profiles)
    }
}

impl Default for BaselineScorer {
    fn default() -> Self {
        Self::new()
    }
}

/// Haversine distance calculation (nm)
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
    fn test_baseline_scoring() {
        let mut scorer = BaselineScorer::new();

        // Establish baseline
        for _ in 0..15 {
            scorer.observe(0x123456, "BA9", 40.0, -73.0, 35000, 450.0);
        }

        // Normal observation
        let risk1 = scorer.score_deviation(0x123456, 40.1, -72.9, 35500, 460.0);
        assert!(risk1 < 0.5);

        // Anomalous observation
        let risk2 = scorer.score_deviation(0x123456, 0.0, 0.0, 10000, 900.0);
        assert!(risk2 > 0.5);
    }
}
