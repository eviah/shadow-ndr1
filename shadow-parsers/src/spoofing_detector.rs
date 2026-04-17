//! RF Spoofing Detection via Statistical Ensemble
//!
//! Detects spoofed ADS-B transmissions using:
//! - RF fingerprinting (RSSI, frequency offset, signal rise time)
//! - Ghost aircraft (ADS-B only, no MLAT/radar corroboration)
//! - Cloned ICAO addresses

use lru::LruCache;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::num::NonZeroUsize;

/// RF Fingerprint per aircraft
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RfFingerprint {
    /// Mean RSSI (dBm)
    pub rssi_mean: f32,
    /// RSSI standard deviation
    pub rssi_std: f32,
    /// Frequency offset in PPM (parts per million)
    pub ppm_offset: f32,
    /// Signal rise time (nanoseconds)
    pub rise_time_ns: u32,
    /// Number of samples
    pub sample_count: u32,
}

/// Spoofing indicators
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub enum SpoofingIndicator {
    /// RF signature doesn't match baseline
    InconsistentRfSignature {
        /// ICAO24 address
        icao24: u32,
        /// Confidence 0.0-1.0
        confidence: f32,
    },
    /// Aircraft reports ADS-B but no MLAT/radar corroboration
    GhostAircraft {
        /// ICAO24 address
        icao24: u32,
    },
    /// Same ICAO24 from multiple geographic locations
    ClonedIcao {
        /// ICAO24 address
        icao24: u32,
    },
}

/// Spoofing detector engine
pub struct SpoofingDetector {
    /// RF fingerprints per ICAO24
    rf_fingerprints: LruCache<u32, RfFingerprint>,
    /// Suspected ghost aircraft
    ghost_aircraft: HashSet<u32>,
    /// Known good locations per ICAO24 (lat, lon)
    last_positions: LruCache<u32, (f64, f64)>,
}

impl SpoofingDetector {
    /// Create new spoofing detector (capacity 5000 aircraft)
    pub fn new() -> Self {
        SpoofingDetector {
            rf_fingerprints: LruCache::new(NonZeroUsize::new(5000).unwrap()),
            ghost_aircraft: HashSet::new(),
            last_positions: LruCache::new(NonZeroUsize::new(5000).unwrap()),
        }
    }

    /// Analyze fingerprint and detect spoofing
    pub fn analyze(&mut self, icao24: u32, fp: RfFingerprint) -> Vec<SpoofingIndicator> {
        let mut indicators = Vec::new();

        // Check RF signature consistency
        if let Some(baseline) = self.rf_fingerprints.peek(&icao24) {
            let rssi_deviation = (fp.rssi_mean - baseline.rssi_mean).abs();
            let ppm_deviation = (fp.ppm_offset - baseline.ppm_offset).abs();

            // Large deviations suggest spoofing
            if rssi_deviation > 15.0 || ppm_deviation > 50.0 {
                let confidence = (rssi_deviation / 30.0).min(1.0);
                indicators.push(SpoofingIndicator::InconsistentRfSignature {
                    icao24,
                    confidence,
                });
            }
        }

        // Update fingerprint
        self.rf_fingerprints.put(icao24, fp);

        indicators
    }

    /// Mark aircraft as ghost (ADS-B without MLAT/radar corroboration)
    pub fn mark_ghost(&mut self, icao24: u32) -> SpoofingIndicator {
        self.ghost_aircraft.insert(icao24);
        SpoofingIndicator::GhostAircraft { icao24 }
    }

    /// Check position consistency (detects cloned ICAO)
    pub fn check_position(&mut self, icao24: u32, lat: f64, lon: f64) -> Option<SpoofingIndicator> {
        if let Some(last_pos) = self.last_positions.peek(&icao24) {
            // Simple distance check: if >1000km in <1 minute, likely cloned
            let dlat = lat - last_pos.0;
            let dlon = lon - last_pos.1;
            let dist_km = ((dlat * dlat + dlon * dlon).sqrt()) * 111.0; // rough conversion

            if dist_km > 1000.0 {
                return Some(SpoofingIndicator::ClonedIcao { icao24 });
            }
        }

        self.last_positions.put(icao24, (lat, lon));
        None
    }

    /// Get list of suspected ghost aircraft
    pub fn get_ghost_aircraft(&self) -> Vec<u32> {
        self.ghost_aircraft.iter().copied().collect()
    }
}

impl Default for SpoofingDetector {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detector_creation() {
        let detector = SpoofingDetector::new();
        assert_eq!(detector.ghost_aircraft.len(), 0);
    }

    #[test]
    fn test_rf_signature_analysis() {
        let mut detector = SpoofingDetector::new();

        let fp1 = RfFingerprint {
            rssi_mean: -50.0,
            rssi_std: 2.0,
            ppm_offset: 10.0,
            rise_time_ns: 50,
            sample_count: 100,
        };

        let indicators = detector.analyze(0x123456, fp1);
        assert!(indicators.is_empty()); // First sample, no baseline yet

        // Now with deviation
        let fp2 = RfFingerprint {
            rssi_mean: -30.0, // +20dB deviation
            rssi_std: 3.0,
            ppm_offset: 15.0,
            rise_time_ns: 55,
            sample_count: 100,
        };

        let indicators = detector.analyze(0x123456, fp2);
        assert!(!indicators.is_empty());
    }

    #[test]
    fn test_ghost_aircraft_marking() {
        let mut detector = SpoofingDetector::new();
        detector.mark_ghost(0xABCDEF);
        assert_eq!(detector.get_ghost_aircraft().len(), 1);
    }
}
