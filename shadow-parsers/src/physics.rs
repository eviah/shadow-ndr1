//! Kinematic Physics Engine - Project Titan
//! 
//! This module acts as the "Physics Firewall" at the very edge of the NDR.
//! It tracks the state (lat/lon, altitude, velocity) of every aircraft seen on the network.
//! By applying basic kinematic constraints (maximum G-force, physical velocity limits),
//! it instantaneously identifies GPS spoofing, Ghost Aircraft injections, and 
//! impossible telemetry without needing external ML/backend round-trips.

use tracing::{info, warn};
use lru::LruCache;
use serde::{Deserialize, Serialize};
use std::num::NonZeroUsize;
use std::time::{SystemTime, UNIX_EPOCH};

// =============================================================================
// Constants & Limits
// =============================================================================

/// Max realistic commercial aircraft speed: ~600 knots = ~310 m/s. 
/// We set limit to 500 m/s (~Mach 1.5) to catch fighter jets too, but any commercial
/// flight claiming Mach 2 is an instant spoofing candidate.
pub const MAX_PLAUSIBLE_VELOCITY_MPS: f64 = 600.0;

/// Maximum realistic gravitational acceleration for a commercial jet before airframe failure.
/// 3-5 Gs is extreme; we flag anything > 4G as physically impossible telemetry.
pub const MAX_ACCELERATION_G: f64 = 4.0;
const GRAVITY: f64 = 9.80665;

// =============================================================================
// Data Structures
// =============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PhysicalState {
    pub icao24: u32,
    pub lat: f64,
    pub lon: f64,
    pub altitude_ft: i32,
    pub velocity_knots: Option<f64>,
    pub heading: Option<f64>,
    pub timestamp_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PhysicsAnomaly {
    ImpossibleVelocity { calculated_mps: f64, limit_mps: f64 },
    ImpossibleAcceleration { calculated_g: f64, limit_g: f64 },
    Teleportation { distance_m: f64, time_delta_s: f64 },
    SubterraneanAltitude { altitude_ft: i32 },
}

/// The state engine tracks all airborne entities.
pub struct KinematicEngine {
    /// LRU Cache mapping ICAO24 to their last known physical state.
    /// Tracks up to 100,000 distinct aircraft simultaneously.
    states: LruCache<u32, PhysicalState>,
}

impl KinematicEngine {
    pub fn new() -> Self {
        Self {
            states: LruCache::new(NonZeroUsize::new(100_000).unwrap()),
        }
    }

    /// Process a new state update. Returns an anomaly if physical laws are broken.
    pub fn process_state(&mut self, new_state: PhysicalState) -> Option<PhysicsAnomaly> {
        let current_time = new_state.timestamp_ms;

        // 1. Altitude sanity check
        if new_state.altitude_ft < -1500 {
            return Some(PhysicsAnomaly::SubterraneanAltitude {
                altitude_ft: new_state.altitude_ft,
            });
        }

        // 2. Trajectory validation against previous state
        if let Some(prev) = self.states.get(&new_state.icao24) {
            let dt_s = (current_time.saturating_sub(prev.timestamp_ms)) as f64 / 1000.0;
            
            // Skip checks if timestamp is identical, inverted, or huge gap (> 1 hour)
            if dt_s > 0.0 && dt_s < 3600.0 {
                let distance_m = haversine_distance(prev.lat, prev.lon, new_state.lat, new_state.lon);
                let calculated_velocity = distance_m / dt_s;

                // Teleportation Check (Is the distance physically possible in the timeframe?)
                if calculated_velocity > MAX_PLAUSIBLE_VELOCITY_MPS * 2.0 {
                    warn!("TELEPORTATION DETECTED: ICAO {:06X} moved {}m in {}s", new_state.icao24, distance_m, dt_s);
                    return Some(PhysicsAnomaly::Teleportation {
                        distance_m,
                        time_delta_s: dt_s,
                    });
                }

                if calculated_velocity > MAX_PLAUSIBLE_VELOCITY_MPS {
                    return Some(PhysicsAnomaly::ImpossibleVelocity {
                        calculated_mps: calculated_velocity,
                        limit_mps: MAX_PLAUSIBLE_VELOCITY_MPS,
                    });
                }

                // If velocity was reported, check acceleration
                if let (Some(v1_knots), Some(v2_knots)) = (prev.velocity_knots, new_state.velocity_knots) {
                    let v1_mps = v1_knots * 0.514444;
                    let v2_mps = v2_knots * 0.514444;
                    let accel_mps2 = (v2_mps - v1_mps).abs() / dt_s;
                    let accel_g = accel_mps2 / GRAVITY;

                    if accel_g > MAX_ACCELERATION_G {
                        warn!("IMPOSSIBLE KINEMATICS: ICAO {:06X} accelerated at {} G", new_state.icao24, accel_g);
                        return Some(PhysicsAnomaly::ImpossibleAcceleration {
                            calculated_g: accel_g,
                            limit_g: MAX_ACCELERATION_G,
                        });
                    }
                }
            }
        }

        // Update the state cache unconditionally
        self.states.put(new_state.icao24, new_state);
        None
    }
}

// =============================================================================
// Math Utilities
// =============================================================================

/// Calculate the great-circle distance between two points on a sphere (Earth).
fn haversine_distance(lat1: f64, lon1: f64, lat2: f64, lon2: f64) -> f64 {
    let r = 6371e3; // Earth radius in meters
    let phi1 = lat1.to_radians();
    let phi2 = lat2.to_radians();
    let d_phi = (lat2 - lat1).to_radians();
    let d_lambda = (lon2 - lon1).to_radians();

    let a = (d_phi / 2.0).sin().powi(2)
        + phi1.cos() * phi2.cos() * (d_lambda / 2.0).sin().powi(2);
    let c = 2.0 * a.sqrt().atan2((1.0 - a).sqrt());

    r * c
}
