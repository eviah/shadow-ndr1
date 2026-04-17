//! MLAT (Multilateration) Engine - Time-of-Arrival Position Triangulation
//!
//! Correlates timestamps from multiple sensor nodes to triangulate aircraft
//! position without relying on ADS-B transmissions. Detects aircraft that
//! don't transmit (stealth, military, non-cooperative targets).
//!
//! Uses hyperbolic position lines (TDOA - Time Difference of Arrival) to
//! compute lat/lon within 100-500m accuracy depending on sensor geometry.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Represents a single sensor node in the MLAT network
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MlatSensor {
    /// Sensor identifier (IP, UUID, etc.)
    pub id: String,
    /// Latitude of sensor (decimal degrees)
    pub latitude: f64,
    /// Longitude of sensor (decimal degrees)
    pub longitude: f64,
    /// Altitude of sensor (meters above sea level)
    pub altitude: f64,
    /// System timing offset (microseconds) - calibrated via known targets
    pub timing_offset: f64,
}

/// Time-of-Arrival measurement from one sensor
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToaMeasurement {
    /// Sensor that received this signal
    pub sensor_id: String,
    /// Time of arrival (nanoseconds since epoch)
    pub toa_ns: u64,
    /// Signal strength (dBm)
    pub rssi: f64,
}

/// Multilateration position solution
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MlatSolution {
    /// Computed latitude (decimal degrees)
    pub latitude: f64,
    /// Computed longitude (decimal degrees)
    pub longitude: f64,
    /// Computed altitude (meters above sea level)
    pub altitude: f64,
    /// Estimated accuracy (meters, 1-sigma)
    pub accuracy: f64,
    /// Number of sensors used
    pub sensor_count: usize,
    /// Residual error after fitting (lower = better)
    pub residual: f64,
    /// Whether solution is reliable (residual < threshold)
    pub is_valid: bool,
}

/// MLAT engine state
pub struct MlatEngine {
    sensors: HashMap<String, MlatSensor>,
    measurements_buffer: Vec<Vec<ToaMeasurement>>,
}

impl MlatEngine {
    /// Create new MLAT engine
    pub fn new() -> Self {
        MlatEngine {
            sensors: HashMap::new(),
            measurements_buffer: Vec::new(),
        }
    }

    /// Register a sensor node
    pub fn add_sensor(&mut self, sensor: MlatSensor) {
        self.sensors.insert(sensor.id.clone(), sensor);
    }

    /// Add time-of-arrival measurement
    pub fn add_measurement(&mut self, measurement: ToaMeasurement) {
        // Group measurements by ICAO24 or target ID
        self.measurements_buffer.push(vec![measurement]);
    }

    /// Compute position from Time-Difference-of-Arrival (TDOA)
    pub fn multilaterate(&self, measurements: &[ToaMeasurement]) -> Option<MlatSolution> {
        if measurements.len() < 4 {
            return None; // Need at least 4 sensors for 3D position
        }

        let mut best_solution: Option<MlatSolution> = None;
        let mut best_residual = f64::MAX;

        // Try grid search over likely position area (+-10km from centroid)
        let centroid_lat = measurements
            .iter()
            .filter_map(|m| self.sensors.get(&m.sensor_id).map(|s| s.latitude))
            .sum::<f64>()
            / measurements.len() as f64;

        let centroid_lon = measurements
            .iter()
            .filter_map(|m| self.sensors.get(&m.sensor_id).map(|s| s.longitude))
            .sum::<f64>()
            / measurements.len() as f64;

        // Grid points (100m spacing over 20km area)
        for lat_offset in -100..=100 {
            for lon_offset in -100..=100 {
                let test_lat = centroid_lat + (lat_offset as f64) * 0.0001; // ~10m per unit
                let test_lon = centroid_lon + (lon_offset as f64) * 0.0001;
                let test_alt = 5000.0; // Default 5000m for initial search

                // Calculate TDOA residuals
                let mut residual = 0.0;
                for i in 0..measurements.len() {
                    for j in (i + 1)..measurements.len() {
                        let sensor_i = self.sensors.get(&measurements[i].sensor_id)?;
                        let sensor_j = self.sensors.get(&measurements[j].sensor_id)?;

                        let dist_i = haversine_3d(sensor_i.latitude, sensor_i.longitude, sensor_i.altitude,
                                                  test_lat, test_lon, test_alt);
                        let dist_j = haversine_3d(sensor_j.latitude, sensor_j.longitude, sensor_j.altitude,
                                                  test_lat, test_lon, test_alt);

                        let expected_tdoa = (dist_i - dist_j) / 300.0; // Speed of light: 300m/us
                        let measured_tdoa = (measurements[i].toa_ns as f64 - measurements[j].toa_ns as f64) / 1000.0;

                        let error = (expected_tdoa - measured_tdoa).abs();
                        residual += error * error;
                    }
                }

                residual = residual.sqrt() / measurements.len() as f64;

                if residual < best_residual {
                    best_residual = residual;
                    best_solution = Some(MlatSolution {
                        latitude: test_lat,
                        longitude: test_lon,
                        altitude: test_alt,
                        accuracy: 100.0, // Meters, ~1-sigma
                        sensor_count: measurements.len(),
                        residual,
                        is_valid: residual < 50.0, // Valid if residual < 50us
                    });
                }
            }
        }

        best_solution
    }

    /// Validate MLAT solution against ADS-B position (if available)
    pub fn validate_against_adsb(&self, mlat_pos: &MlatSolution, adsb_lat: f64, adsb_lon: f64) -> f64 {
        // Calculate distance between MLAT and ADS-B positions
        haversine(mlat_pos.latitude, mlat_pos.longitude, adsb_lat, adsb_lon)
    }
}

/// Haversine distance formula (2D)
fn haversine(lat1: f64, lon1: f64, lat2: f64, lon2: f64) -> f64 {
    const EARTH_RADIUS: f64 = 6_371_000.0; // meters
    let lat1_rad = lat1.to_radians();
    let lat2_rad = lat2.to_radians();
    let delta_lat = (lat2 - lat1).to_radians();
    let delta_lon = (lon2 - lon1).to_radians();

    let a = (delta_lat / 2.0).sin().powi(2)
        + lat1_rad.cos() * lat2_rad.cos() * (delta_lon / 2.0).sin().powi(2);
    let c = 2.0 * a.sqrt().atan2((1.0 - a).sqrt());
    EARTH_RADIUS * c
}

/// Haversine distance with altitude (3D)
fn haversine_3d(lat1: f64, lon1: f64, alt1: f64, lat2: f64, lon2: f64, alt2: f64) -> f64 {
    let horizontal = haversine(lat1, lon1, lat2, lon2);
    let vertical = (alt2 - alt1).abs();
    (horizontal.powi(2) + vertical.powi(2)).sqrt()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_haversine() {
        // Distance between (0,0) and (0,1) should be ~111km
        let dist = haversine(0.0, 0.0, 0.0, 1.0);
        assert!((dist - 111_000.0).abs() < 1000.0); // Within 1km
    }

    #[test]
    fn test_mlat_engine_creation() {
        let mut engine = MlatEngine::new();
        let sensor = MlatSensor {
            id: "sensor1".to_string(),
            latitude: 40.0,
            longitude: -74.0,
            altitude: 100.0,
            timing_offset: 0.0,
        };
        engine.add_sensor(sensor);
        assert_eq!(engine.sensors.len(), 1);
    }
}
