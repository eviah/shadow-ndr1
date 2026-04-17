//! Geofencing & Restricted Airspace Detection
//!
//! Detects violations of:
//! - Restricted airspace (Class A, B, C, D, E)
//! - Military zones
//! - Danger areas
//! - Temporary Flight Restrictions (TFR)
//! - NOTAMs

use serde::{Deserialize, Serialize};

/// Airspace zone type
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum ZoneType {
    /// Class B airspace (commercial controlled)
    ClassB,
    /// Class C airspace (commercial controlled)
    ClassC,
    /// Military training route
    MilitaryTrainingRoute,
    /// Restricted airspace
    Restricted,
    /// Prohibited airspace
    Prohibited,
    /// Danger area
    Danger,
    /// Temporary Flight Restriction
    TemporaryFlightRestriction,
    /// Other
    Other,
}

/// Geofence zone definition
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GeofenceZone {
    /// Zone identifier
    pub zone_id: String,
    /// Zone type
    pub zone_type: ZoneType,
    /// Polygon vertices (latitude, longitude)
    pub bounds: Vec<(f64, f64)>,
    /// Minimum altitude (feet), -1 = surface level
    pub min_altitude_ft: i32,
    /// Maximum altitude (feet), -1 = unlimited
    pub max_altitude_ft: i32,
    /// Associated NOTAM ID if any
    pub notam_id: Option<String>,
}

/// Geofence violation
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GeofenceViolation {
    /// ICAO24 address
    pub icao24: u32,
    /// Zone that was violated
    pub zone_id: String,
    /// Zone type
    pub zone_type: ZoneType,
    /// Current position (lat, lon)
    pub latitude: f64,
    pub longitude: f64,
    /// Current altitude (feet)
    pub altitude_ft: i32,
    /// Severity (0-10)
    pub severity: u8,
}

/// Geofence engine
pub struct GeofenceEngine {
    /// Active zones
    zones: Vec<GeofenceZone>,
}

impl GeofenceEngine {
    /// Create new geofence engine
    pub fn new() -> Self {
        GeofenceEngine {
            zones: Vec::new(),
        }
    }

    /// Add a zone
    pub fn add_zone(&mut self, zone: GeofenceZone) {
        self.zones.push(zone);
    }

    /// Check position against all zones
    pub fn check(&self, icao24: u32, lat: f64, lon: f64, alt_ft: i32) -> Vec<GeofenceViolation> {
        let mut violations = Vec::new();

        for zone in &self.zones {
            // Check altitude bounds
            if alt_ft < zone.min_altitude_ft || (zone.max_altitude_ft > 0 && alt_ft > zone.max_altitude_ft) {
                continue; // Outside altitude range
            }

            // Check point-in-polygon (ray casting)
            if self.point_in_polygon(lat, lon, &zone.bounds) {
                let severity = match zone.zone_type {
                    ZoneType::Prohibited => 10,
                    ZoneType::Restricted => 9,
                    ZoneType::MilitaryTrainingRoute => 8,
                    ZoneType::TemporaryFlightRestriction => 8,
                    ZoneType::Danger => 7,
                    ZoneType::ClassB | ZoneType::ClassC => 6,
                    _ => 5,
                };

                violations.push(GeofenceViolation {
                    icao24,
                    zone_id: zone.zone_id.clone(),
                    zone_type: zone.zone_type.clone(),
                    latitude: lat,
                    longitude: lon,
                    altitude_ft: alt_ft,
                    severity,
                });
            }
        }

        violations
    }

    /// Load zones from JSON string
    pub fn load_from_json(&mut self, json: &str) -> Result<usize, String> {
        match serde_json::from_str::<Vec<GeofenceZone>>(json) {
            Ok(zones) => {
                let count = zones.len();
                self.zones.extend(zones);
                Ok(count)
            }
            Err(e) => Err(format!("JSON parse error: {}", e)),
        }
    }

    /// Point-in-polygon using ray casting algorithm
    fn point_in_polygon(&self, lat: f64, lon: f64, polygon: &[(f64, f64)]) -> bool {
        if polygon.len() < 3 {
            return false;
        }

        let mut inside = false;
        let mut j = polygon.len() - 1;

        for i in 0..polygon.len() {
            let xi = polygon[i].1;
            let yi = polygon[i].0;
            let xj = polygon[j].1;
            let yj = polygon[j].0;

            let intersect = ((yi > lat) != (yj > lat))
                && (lon < (xj - xi) * (lat - yi) / (yj - yi) + xi);
            if intersect {
                inside = !inside;
            }
            j = i;
        }

        inside
    }

    /// Get number of active zones
    pub fn zone_count(&self) -> usize {
        self.zones.len()
    }

    /// Clear all zones
    pub fn clear(&mut self) {
        self.zones.clear();
    }
}

impl Default for GeofenceEngine {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_geofence_creation() {
        let engine = GeofenceEngine::new();
        assert_eq!(engine.zone_count(), 0);
    }

    #[test]
    fn test_add_zone() {
        let mut engine = GeofenceEngine::new();
        let zone = GeofenceZone {
            zone_id: "TEST-001".to_string(),
            zone_type: ZoneType::Prohibited,
            bounds: vec![(40.0, -74.0), (41.0, -74.0), (41.0, -73.0), (40.0, -73.0)],
            min_altitude_ft: 0,
            max_altitude_ft: 5000,
            notam_id: None,
        };
        engine.add_zone(zone);
        assert_eq!(engine.zone_count(), 1);
    }

    #[test]
    fn test_point_in_polygon() {
        let engine = GeofenceEngine::new();
        // Simple square
        let polygon = vec![(0.0, 0.0), (1.0, 0.0), (1.0, 1.0), (0.0, 1.0)];

        // Inside
        assert!(engine.point_in_polygon(0.5, 0.5, &polygon));
        // Outside
        assert!(!engine.point_in_polygon(2.0, 2.0, &polygon));
    }

    #[test]
    fn test_geofence_violation() {
        let mut engine = GeofenceEngine::new();
        let zone = GeofenceZone {
            zone_id: "NYC-CLASS-B".to_string(),
            zone_type: ZoneType::ClassB,
            bounds: vec![(40.6, -74.0), (41.0, -74.0), (41.0, -73.5), (40.6, -73.5)],
            min_altitude_ft: 0,
            max_altitude_ft: 10000,
            notam_id: None,
        };
        engine.add_zone(zone);

        let violations = engine.check(0x123456, 40.8, -73.8, 5000);
        assert_eq!(violations.len(), 1);
        assert_eq!(violations[0].severity, 6);
    }
}
