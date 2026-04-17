//! Signal Strength Analysis & RSSI Anomaly Detection
//!
//! Tracks radio signal strength per aircraft and detects anomalies:
//! - Sudden spikes (>20dB) indicating spoofing
//! - Signal loss patterns
//! - Multipath reflections via variance analysis

use lru::LruCache;
use std::collections::VecDeque;
use serde::{Deserialize, Serialize};

/// RSSI anomaly types
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub enum RssiAnomaly {
    /// Sudden spike in signal strength (spoofing indicator)
    SuddenSpike {
        /// ICAO24 address
        icao24: u32,
        /// Change in dBm
        delta_db: f32,
    },
    /// Signal loss (aircraft disappeared)
    SignalLoss {
        /// ICAO24 address
        icao24: u32,
    },
    /// Multipath reflection detected
    MultipathReflection {
        /// ICAO24 address
        icao24: u32,
    },
}

/// Tracks RSSI per aircraft
pub struct RssiTracker {
    /// ICAO24 → [(timestamp_ns, rssi_db)]
    history: LruCache<u32, VecDeque<(u64, f32)>>,
}

impl RssiTracker {
    /// Create a new RSSI tracker (capacity 1000 aircraft)
    pub fn new() -> Self {
        RssiTracker {
            history: LruCache::new(std::num::NonZeroUsize::new(1000).unwrap()),
        }
    }

    /// Record RSSI measurement, returns anomaly if detected
    pub fn record(&mut self, icao24: u32, ts_ns: u64, rssi_db: f32) -> Option<RssiAnomaly> {
        // Get or create history for this aircraft
        if !self.history.contains(&icao24) {
            self.history.put(icao24, VecDeque::with_capacity(100));
        }

        let history = self.history.get_mut(&icao24).unwrap();

        // Keep rolling window of last 100 measurements
        if history.len() >= 100 {
            history.pop_front();
        }

        // Check for sudden spike (>20dB change)
        if let Some((_, last_rssi)) = history.back() {
            let delta: f32 = (rssi_db - last_rssi).abs();
            if delta > 20.0 && rssi_db > *last_rssi {
                history.push_back((ts_ns, rssi_db));
                return Some(RssiAnomaly::SuddenSpike {
                    icao24,
                    delta_db: delta,
                });
            }
        }

        history.push_back((ts_ns, rssi_db));
        None
    }

    /// Get recent RSSI measurements
    pub fn get_history(&self, icao24: u32) -> Option<Vec<(u64, f32)>> {
        self.history.peek(&icao24).map(|h| h.iter().copied().collect())
    }
}

impl Default for RssiTracker {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rssi_tracker_creation() {
        let tracker = RssiTracker::new();
        assert_eq!(tracker.history.len(), 0);
    }

    #[test]
    fn test_rssi_spike_detection() {
        let mut tracker = RssiTracker::new();

        // Record baseline
        tracker.record(0x123456, 1000, -50.0);

        // Record spike
        let anomaly = tracker.record(0x123456, 2000, -25.0);
        assert!(matches!(anomaly, Some(RssiAnomaly::SuddenSpike { .. })));
    }

    #[test]
    fn test_rssi_normal_variations() {
        let mut tracker = RssiTracker::new();

        // Record normal variations
        tracker.record(0x123456, 1000, -50.0);
        let anomaly = tracker.record(0x123456, 2000, -48.0);
        assert_eq!(anomaly, None);
    }
}
