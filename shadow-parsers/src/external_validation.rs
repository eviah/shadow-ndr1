//! External Validation via OpenSky Network
//!
//! Queries external aviation data sources to validate local detections
//! and check for discrepancies in aircraft position/identity.

use serde::{Deserialize, Serialize};
use lru::LruCache;
use std::num::NonZeroUsize;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExternalAircraftState {
    pub icao24: u32,
    pub lat: f64,
    pub lon: f64,
    pub altitude_ft: i32,
    pub callsign: String,
    pub source: String, // "opensky", "adsbexchange", etc.
    pub fetched_at_ms: u64,
}

pub struct ExternalValidator {
    cache: LruCache<u32, ExternalAircraftState>,
    cache_ttl_ms: u64,
}

#[derive(Debug, Clone, Copy)]
pub enum ExternalValidationError {
    NotFound,
    Timeout,
    InvalidResponse,
    NetworkError,
    CacheDisabled,
}

impl ExternalValidator {
    /// Create new external validator with 1000-aircraft cache
    pub fn new() -> Self {
        ExternalValidator {
            cache: LruCache::new(NonZeroUsize::new(1000).unwrap()),
            cache_ttl_ms: 60_000, // 60-second cache TTL
        }
    }

    /// Create with custom cache TTL (milliseconds)
    pub fn with_ttl(ttl_ms: u64) -> Self {
        ExternalValidator {
            cache: LruCache::new(NonZeroUsize::new(1000).unwrap()),
            cache_ttl_ms: ttl_ms,
        }
    }

    /// Get cached state if available and not expired
    pub fn get_cached(&self, icao24: u32, current_time_ms: u64) -> Option<ExternalAircraftState> {
        self.cache.peek(&icao24).and_then(|state| {
            if current_time_ms - state.fetched_at_ms < self.cache_ttl_ms {
                Some(state.clone())
            } else {
                None
            }
        })
    }

    /// Simulate external lookup (in production would be actual HTTP call)
    pub fn lookup(
        &mut self,
        icao24: u32,
        current_time_ms: u64,
    ) -> Result<ExternalAircraftState, ExternalValidationError> {
        // Check cache first
        if let Some(cached) = self.get_cached(icao24, current_time_ms) {
            return Ok(cached);
        }

        // In production, this would query OpenSky Network or similar
        // OpenSky API: https://opensky-network.org/api/states/all?icao24=406417
        // For now, return mock data
        let state = ExternalAircraftState {
            icao24,
            lat: 40.0,
            lon: -73.0,
            altitude_ft: 35000,
            callsign: format!("UNKNOWN"),
            source: "opensky".to_string(),
            fetched_at_ms: current_time_ms,
        };

        // Cache it
        self.cache.put(icao24, state.clone());

        Ok(state)
    }

    /// Check discrepancy between local and external position
    pub fn check_position_discrepancy(
        &mut self,
        icao24: u32,
        local_lat: f64,
        local_lon: f64,
        local_alt_ft: i32,
        current_time_ms: u64,
    ) -> Result<PositionDiscrepancy, ExternalValidationError> {
        let external = self.lookup(icao24, current_time_ms)?;

        let distance_nm = haversine_distance(local_lat, local_lon, external.lat, external.lon);
        let altitude_diff_ft = (local_alt_ft - external.altitude_ft).abs();

        Ok(PositionDiscrepancy {
            icao24,
            distance_nm,
            altitude_diff_ft,
            lat_diff: (local_lat - external.lat).abs(),
            lon_diff: (local_lon - external.lon).abs(),
            is_suspect: distance_nm > 5.0 || altitude_diff_ft > 1000,
        })
    }

    /// Check callsign consistency with external source
    pub fn check_callsign_consistency(
        &mut self,
        icao24: u32,
        local_callsign: &str,
        current_time_ms: u64,
    ) -> Result<CallsignMatch, ExternalValidationError> {
        let external = self.lookup(icao24, current_time_ms)?;

        let exact_match = local_callsign.eq_ignore_ascii_case(&external.callsign);
        let partial_match = local_callsign.len() > 2
            && external.callsign.contains(&local_callsign[..2.min(local_callsign.len())]);

        Ok(CallsignMatch {
            icao24,
            expected_callsign: external.callsign.clone(),
            received_callsign: local_callsign.to_string(),
            exact_match,
            partial_match,
            is_suspect: !exact_match && !partial_match,
        })
    }

    /// Clear all cached entries
    pub fn clear_cache(&mut self) {
        self.cache.clear();
    }
}

impl Default for ExternalValidator {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PositionDiscrepancy {
    pub icao24: u32,
    pub distance_nm: f64,
    pub altitude_diff_ft: i32,
    pub lat_diff: f64,
    pub lon_diff: f64,
    pub is_suspect: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CallsignMatch {
    pub icao24: u32,
    pub expected_callsign: String,
    pub received_callsign: String,
    pub exact_match: bool,
    pub partial_match: bool,
    pub is_suspect: bool,
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
    fn test_external_validator_lookup() {
        let mut validator = ExternalValidator::new();
        let result = validator.lookup(0x406417, 1000);
        assert!(result.is_ok());
        let state = result.unwrap();
        assert_eq!(state.icao24, 0x406417);
    }

    #[test]
    fn test_cache_ttl() {
        let mut validator = ExternalValidator::with_ttl(100);
        let _ = validator.lookup(0x406417, 1000);

        let cached = validator.get_cached(0x406417, 1050);
        assert!(cached.is_some());

        let expired = validator.get_cached(0x406417, 2000);
        assert!(expired.is_none());
    }

    #[test]
    fn test_position_discrepancy() {
        let mut validator = ExternalValidator::new();
        let result = validator.check_position_discrepancy(0x406417, 40.1, -73.1, 35100, 1000);
        assert!(result.is_ok());
        let discrepancy = result.unwrap();
        assert!(discrepancy.distance_nm > 0.0);
    }

    #[test]
    fn test_callsign_match() {
        let mut validator = ExternalValidator::new();
        let result = validator.check_callsign_consistency(0x406417, "AAL1234", 1000);
        assert!(result.is_ok());
    }
}
