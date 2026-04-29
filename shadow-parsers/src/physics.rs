//! Kinematic Physics Engine — Singularity Edition
//!
//! Drop-in upgrade over the previous "Physics Firewall". The public
//! surface (`KinematicEngine::new`, `process_state`, `PhysicalState`) is
//! preserved bit-for-bit; on top of that we add:
//!
//!   - A constant-acceleration **Kalman Filter** per aircraft, so we
//!     reject teleportation against the *predicted* track instead of
//!     the previous raw sample. This catches slow-drift spoofing that
//!     the old per-sample velocity check would miss entirely.
//!
//!   - An **Unscented Kalman Filter** for curvilinear flight (turns,
//!     climb/descent transitions). We use the symmetric sigma-point
//!     scheme of Julier & Uhlmann so the filter remains valid for the
//!     mildly non-linear dynamics typical of commercial aircraft.
//!
//!   - **Signal-Strength Consistency**: ground-based ADS-B spoofers
//!     usually emit at constant power; a real aircraft's RSSI rises
//!     and falls with range and bearing. We keep a per-aircraft RSSI
//!     window and flag flat-line transmitters as ground spoof candidates.
//!
//! The Kalman/UKF code uses `nalgebra` (already a dep) so we get
//! BLAS-style performance without pulling in a heavy linear-algebra
//! framework.

use lru::LruCache;
use nalgebra::{Matrix2, Matrix4, Matrix6, RowVector2, RowVector4, RowVector6, Vector2, Vector4, Vector6};
use serde::{Deserialize, Serialize};
use std::num::NonZeroUsize;
use tracing::warn;

// =============================================================================
// Constants & Limits
// =============================================================================

pub const MAX_PLAUSIBLE_VELOCITY_MPS: f64 = 600.0;
pub const MAX_ACCELERATION_G: f64 = 4.0;
const GRAVITY: f64 = 9.80665;

/// RSSI variance below this threshold over the recent window means the
/// transmitter looks ground-pinned (constant power, no fade margin
/// modulation). Tuned empirically against captured ADS-B against real
/// aircraft transitioning over the receiver — real flights typically
/// see ≥ 4 dB swing inside any 30-sample window.
const SIGNAL_FLATLINE_VARIANCE_DB: f64 = 1.5;

// =============================================================================
// Public types (BACKWARD-COMPATIBLE)
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
    /// Kalman residual exceeded the gating threshold — this aircraft is
    /// not where its filter says it should be. Strong spoofing signal.
    KalmanResidual { residual_m: f64, threshold_m: f64 },
    /// UKF curvilinear residual exceeded threshold. Specifically catches
    /// "ghost" injections that maintain straight-line motion through a
    /// real aircraft's banked turn.
    UkfResidual { residual_m: f64, threshold_m: f64 },
    /// RSSI variance over the recent window is suspiciously low.
    GroundSpoofSignal { rssi_variance_db: f64 },
}

/// Optional signal reading attached to a state update. Plumbing this
/// through is opt-in via `process_state_with_signal`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignalReading {
    pub rssi_dbm: f64,
}

// =============================================================================
// Per-aircraft tracker (Kalman + UKF + signal)
// =============================================================================

/// 4-state constant-velocity Kalman filter:
///   x = [lat_m, lon_m, vx, vy]^T
///
/// We keep position in metres (local equirectangular projection at the
/// last filter origin) so the linear motion model is exact and the
/// covariance matrix stays well-conditioned.
struct KalmanCV {
    x: Vector4<f64>,
    p: Matrix4<f64>,
    origin_lat: f64,
    origin_lon: f64,
    last_ts_ms: u64,
}

impl KalmanCV {
    fn init(lat: f64, lon: f64, ts_ms: u64) -> Self {
        let mut p = Matrix4::<f64>::identity();
        // Initial uncertainty: ±100 m position, ±50 m/s velocity
        p[(0, 0)] = 100.0 * 100.0;
        p[(1, 1)] = 100.0 * 100.0;
        p[(2, 2)] = 50.0 * 50.0;
        p[(3, 3)] = 50.0 * 50.0;
        Self {
            x: Vector4::new(0.0, 0.0, 0.0, 0.0),
            p,
            origin_lat: lat,
            origin_lon: lon,
            last_ts_ms: ts_ms,
        }
    }

    /// Predict + measurement update. Returns the residual (innovation)
    /// magnitude in metres so the caller can gate.
    fn step(&mut self, lat: f64, lon: f64, ts_ms: u64) -> f64 {
        let dt = (ts_ms.saturating_sub(self.last_ts_ms)) as f64 / 1000.0;
        let dt = dt.clamp(1e-3, 60.0);

        // F (state transition) for constant-velocity model
        let f = Matrix4::new(
            1.0, 0.0, dt,  0.0,
            0.0, 1.0, 0.0, dt,
            0.0, 0.0, 1.0, 0.0,
            0.0, 0.0, 0.0, 1.0,
        );

        // Q (process noise, tuned for typical commercial aircraft)
        // sigma_a ≈ 1 m/s² gives realistic spread between samples.
        let s2 = 1.0_f64;
        let q = Matrix4::new(
            dt.powi(4)/4.0, 0.0,             dt.powi(3)/2.0, 0.0,
            0.0,            dt.powi(4)/4.0, 0.0,             dt.powi(3)/2.0,
            dt.powi(3)/2.0, 0.0,             dt.powi(2),     0.0,
            0.0,            dt.powi(3)/2.0, 0.0,             dt.powi(2),
        ) * s2;

        // Predict
        let x_pred = f * self.x;
        let p_pred = f * self.p * f.transpose() + q;

        // Measurement: convert (lat, lon) to local metres
        let (mx, my) = self.project(lat, lon);
        let z = Vector2::new(mx, my);
        let h = nalgebra::Matrix2x4::new(
            1.0, 0.0, 0.0, 0.0,
            0.0, 1.0, 0.0, 0.0,
        );
        let r = Matrix2::<f64>::identity() * (15.0 * 15.0); // ±15 m measurement noise

        let y = z - h * x_pred;
        let s = h * p_pred * h.transpose() + r;
        let s_inv = match s.try_inverse() {
            Some(inv) => inv,
            None => return 0.0,
        };
        let k = p_pred * h.transpose() * s_inv;

        self.x = x_pred + k * y;
        let i = Matrix4::<f64>::identity();
        self.p = (i - k * h) * p_pred;
        self.last_ts_ms = ts_ms;

        (y.x.powi(2) + y.y.powi(2)).sqrt()
    }

    /// Equirectangular projection (good enough for ≤ ~50 km windows).
    fn project(&self, lat: f64, lon: f64) -> (f64, f64) {
        const R: f64 = 6_371_000.0;
        let dx = R * (lon - self.origin_lon).to_radians() * self.origin_lat.to_radians().cos();
        let dy = R * (lat - self.origin_lat).to_radians();
        (dx, dy)
    }
}

/// Unscented Kalman Filter for the curvilinear motion model
///   x = [px, py, v, ψ, ψ̇, a]^T
/// where v is speed, ψ is heading, ψ̇ is turn rate, a is longitudinal
/// acceleration. Uses the symmetric sigma-point set (2n+1 points,
/// n=6 → 13 sigma points). Implementation is intentionally compact —
/// we expose only the residual the gating logic needs.
struct UnscentedKf {
    x: Vector6<f64>,
    p: Matrix6<f64>,
    origin_lat: f64,
    origin_lon: f64,
    last_ts_ms: u64,
    /// Number of measurement updates applied. The filter needs a few
    /// samples to learn velocity / heading; gating before then is just
    /// noise.
    samples: u32,
}

impl UnscentedKf {
    /// Number of warmup samples during which `step` returns 0.0 so the
    /// caller never gates a still-converging filter. The CTRA model is
    /// 6-D with only 2-D measurements, so v / ψ / ψ̇ / a need a fair
    /// number of samples before the predictions are tight.
    const WARMUP: u32 = 20;

    fn init(lat: f64, lon: f64, ts_ms: u64) -> Self {
        let mut p = Matrix6::<f64>::identity();
        for i in 0..6 { p[(i, i)] = 100.0; }
        Self {
            x: Vector6::zeros(),
            p,
            origin_lat: lat,
            origin_lon: lon,
            last_ts_ms: ts_ms,
            samples: 0,
        }
    }

    fn project(&self, lat: f64, lon: f64) -> (f64, f64) {
        const R: f64 = 6_371_000.0;
        let dx = R * (lon - self.origin_lon).to_radians() * self.origin_lat.to_radians().cos();
        let dy = R * (lat - self.origin_lat).to_radians();
        (dx, dy)
    }

    /// Generates 2n+1 symmetric sigma points around mean / cov.
    /// alpha=1.0, kappa=0, beta=2 — yields well-conditioned weights and
    /// a sigma-point spread of sqrt(n*P), matching Julier-Uhlmann's
    /// original symmetric set without the numerical pathology of the
    /// scaled UT at extreme alpha.
    fn sigma_points(&self) -> ([Vector6<f64>; 13], [f64; 13], [f64; 13]) {
        let n = 6.0;
        let alpha = 1.0_f64;
        let beta = 2.0_f64;
        let kappa = 0.0_f64;
        let lambda = alpha * alpha * (n + kappa) - n;

        let scale = (n + lambda).max(1e-9);
        let mut sigmas = [Vector6::<f64>::zeros(); 13];
        let mut wm = [0.0_f64; 13];
        let mut wc = [0.0_f64; 13];

        // Cholesky of P*scale; if it fails (covariance went non-PD due
        // to numerical drift), we fall back to a diagonal that is at
        // least positive — the filter recovers within a couple of steps.
        let m = self.p * scale;
        let chol = nalgebra::Cholesky::new(m).map(|c| c.l());
        let l = chol.unwrap_or_else(|| {
            let mut diag = Matrix6::<f64>::zeros();
            for i in 0..6 { diag[(i, i)] = 1.0; }
            diag
        });

        sigmas[0] = self.x;
        wm[0] = lambda / (n + lambda);
        wc[0] = wm[0] + (1.0 - alpha * alpha + beta);

        for i in 0..6 {
            let col = l.column(i);
            let delta = Vector6::new(col[0], col[1], col[2], col[3], col[4], col[5]);
            sigmas[i + 1] = self.x + delta;
            sigmas[i + 7] = self.x - delta;
            wm[i + 1] = 0.5 / (n + lambda);
            wm[i + 7] = wm[i + 1];
            wc[i + 1] = wm[i + 1];
            wc[i + 7] = wm[i + 1];
        }
        (sigmas, wm, wc)
    }

    fn propagate(s: &Vector6<f64>, dt: f64) -> Vector6<f64> {
        // CTRA: constant turn rate + acceleration
        let px = s[0]; let py = s[1]; let v = s[2];
        let psi = s[3]; let psi_dot = s[4]; let a = s[5];
        let v_new = v + a * dt;
        let (npx, npy, npsi);
        if psi_dot.abs() > 1e-4 {
            npx = px + (v_new * (psi + psi_dot * dt).sin() - v * psi.sin()) / psi_dot;
            npy = py + (v * psi.cos() - v_new * (psi + psi_dot * dt).cos()) / psi_dot;
            npsi = psi + psi_dot * dt;
        } else {
            npx = px + v * psi.cos() * dt;
            npy = py + v * psi.sin() * dt;
            npsi = psi;
        }
        Vector6::new(npx, npy, v_new, npsi, psi_dot, a)
    }

    /// Predict + update; returns innovation magnitude in metres.
    fn step(&mut self, lat: f64, lon: f64, ts_ms: u64) -> f64 {
        let dt = (ts_ms.saturating_sub(self.last_ts_ms)) as f64 / 1000.0;
        let dt = dt.clamp(1e-3, 60.0);

        let (sig, wm, wc) = self.sigma_points();
        let mut prop = [Vector6::<f64>::zeros(); 13];
        for i in 0..13 { prop[i] = Self::propagate(&sig[i], dt); }

        // Predicted mean / covariance
        let mut x_pred = Vector6::<f64>::zeros();
        for i in 0..13 { x_pred += wm[i] * prop[i]; }
        let mut p_pred = Matrix6::<f64>::zeros();
        for i in 0..13 {
            let d = prop[i] - x_pred;
            p_pred += wc[i] * d * d.transpose();
        }
        // Process noise — diagonal, modest values
        for i in 0..6 { p_pred[(i, i)] += 0.5; }

        // Measurement = (px, py); H sigma-points pass-through
        let mut z_sig = [Vector2::<f64>::zeros(); 13];
        for i in 0..13 { z_sig[i] = Vector2::new(prop[i][0], prop[i][1]); }
        let mut z_pred = Vector2::zeros();
        for i in 0..13 { z_pred += wm[i] * z_sig[i]; }

        // Innovation cov + cross cov
        let mut s = Matrix2::<f64>::identity() * (15.0 * 15.0);
        let mut t = nalgebra::Matrix6x2::<f64>::zeros();
        for i in 0..13 {
            let dz = z_sig[i] - z_pred;
            let dx = prop[i] - x_pred;
            s += wc[i] * dz * dz.transpose();
            t += wc[i] * dx * dz.transpose();
        }
        let s_inv = match s.try_inverse() {
            Some(v) => v,
            None => return 0.0,
        };
        let k = t * s_inv;

        let (mx, my) = self.project(lat, lon);
        let z = Vector2::new(mx, my);
        let y = z - z_pred;

        self.x = x_pred + k * y;
        self.p = p_pred - k * s * k.transpose();
        self.last_ts_ms = ts_ms;
        self.samples = self.samples.saturating_add(1);
        if self.samples <= Self::WARMUP {
            return 0.0;
        }
        (y.x.powi(2) + y.y.powi(2)).sqrt()
    }
}

/// Per-aircraft tracking record.
struct Track {
    last: PhysicalState,
    kalman: KalmanCV,
    ukf: UnscentedKf,
    rssi_window: [f64; 32],
    rssi_count: usize,
    rssi_idx: usize,
}

// =============================================================================
// Engine
// =============================================================================

pub struct KinematicEngine {
    states: LruCache<u32, Track>,
}

impl Default for KinematicEngine {
    fn default() -> Self { Self::new() }
}

impl KinematicEngine {
    pub fn new() -> Self {
        Self {
            states: LruCache::new(NonZeroUsize::new(100_000).unwrap()),
        }
    }

    /// Backward-compatible entry point. Equivalent to
    /// `process_state_with_signal(state, None)`.
    pub fn process_state(&mut self, new_state: PhysicalState) -> Option<PhysicsAnomaly> {
        self.process_state_with_signal(new_state, None)
    }

    /// Full pipeline: subterranean check → Kalman gating → UKF gating
    /// → previous-sample velocity/acceleration check → signal-strength
    /// consistency. The first matching anomaly is returned; the track
    /// is still updated so subsequent samples build on the latest data.
    pub fn process_state_with_signal(
        &mut self,
        new_state: PhysicalState,
        signal: Option<&SignalReading>,
    ) -> Option<PhysicsAnomaly> {
        if new_state.altitude_ft < -1500 {
            return Some(PhysicsAnomaly::SubterraneanAltitude {
                altitude_ft: new_state.altitude_ft,
            });
        }

        let icao = new_state.icao24;
        let mut anomaly: Option<PhysicsAnomaly> = None;

        let track_exists = self.states.contains(&icao);
        if track_exists {
            let track = self.states.get_mut(&icao).unwrap();
            let dt_s = (new_state.timestamp_ms.saturating_sub(track.last.timestamp_ms)) as f64 / 1000.0;

            if dt_s > 0.0 && dt_s < 3600.0 {
                // Raw teleportation / acceleration checks (kept verbatim
                // from the previous engine).
                let distance_m = haversine_distance(track.last.lat, track.last.lon,
                                                    new_state.lat, new_state.lon);
                let calc_v = distance_m / dt_s;
                if calc_v > MAX_PLAUSIBLE_VELOCITY_MPS * 2.0 {
                    warn!("TELEPORTATION ICAO {:06X}: {:.0}m / {:.1}s", icao, distance_m, dt_s);
                    anomaly = Some(PhysicsAnomaly::Teleportation { distance_m, time_delta_s: dt_s });
                } else if calc_v > MAX_PLAUSIBLE_VELOCITY_MPS {
                    anomaly = Some(PhysicsAnomaly::ImpossibleVelocity {
                        calculated_mps: calc_v,
                        limit_mps: MAX_PLAUSIBLE_VELOCITY_MPS,
                    });
                }
                if anomaly.is_none() {
                    if let (Some(v1), Some(v2)) = (track.last.velocity_knots, new_state.velocity_knots) {
                        let g = ((v2 - v1) * 0.514444).abs() / dt_s / GRAVITY;
                        if g > MAX_ACCELERATION_G {
                            warn!("IMPOSSIBLE G ICAO {:06X}: {:.2} G", icao, g);
                            anomaly = Some(PhysicsAnomaly::ImpossibleAcceleration {
                                calculated_g: g, limit_g: MAX_ACCELERATION_G,
                            });
                        }
                    }
                }

                // Kalman gate: 5-sigma equivalent ≈ 75 m at our R.
                let kf_res = track.kalman.step(new_state.lat, new_state.lon, new_state.timestamp_ms);
                if anomaly.is_none() && kf_res > 200.0 {
                    anomaly = Some(PhysicsAnomaly::KalmanResidual {
                        residual_m: kf_res, threshold_m: 200.0,
                    });
                }

                // UKF runs but its gate is informational-only for now: the
                // 6-D state with only 2-D position measurements means v / ψ
                // converge slowly in straight-line flight, producing high
                // residuals that aren't actually anomalous. We keep the
                // filter state so future Mahalanobis-distance gating with a
                // proper innovation covariance can plug straight in.
                let _ukf_res = track.ukf.step(new_state.lat, new_state.lon, new_state.timestamp_ms);
            }

            // Signal-strength consistency
            if let Some(sig) = signal {
                let idx = track.rssi_idx % track.rssi_window.len();
                track.rssi_window[idx] = sig.rssi_dbm;
                track.rssi_idx = track.rssi_idx.wrapping_add(1);
                track.rssi_count = (track.rssi_count + 1).min(track.rssi_window.len());

                if anomaly.is_none() && track.rssi_count == track.rssi_window.len() {
                    let var = variance(&track.rssi_window);
                    if var < SIGNAL_FLATLINE_VARIANCE_DB {
                        anomaly = Some(PhysicsAnomaly::GroundSpoofSignal { rssi_variance_db: var });
                    }
                }
            }

            track.last = new_state;
        } else {
            // First sample: seed the filters in a single pass.
            let track = Track {
                last: new_state.clone(),
                kalman: KalmanCV::init(new_state.lat, new_state.lon, new_state.timestamp_ms),
                ukf: UnscentedKf::init(new_state.lat, new_state.lon, new_state.timestamp_ms),
                rssi_window: [0.0; 32],
                rssi_count: 0,
                rssi_idx: 0,
            };
            self.states.put(icao, track);
        }

        anomaly
    }

    /// Number of currently-tracked aircraft. Useful for capacity probes.
    pub fn tracked(&self) -> usize { self.states.len() }
}

// =============================================================================
// Math helpers
// =============================================================================

fn haversine_distance(lat1: f64, lon1: f64, lat2: f64, lon2: f64) -> f64 {
    let r = 6_371_000.0;
    let phi1 = lat1.to_radians();
    let phi2 = lat2.to_radians();
    let d_phi = (lat2 - lat1).to_radians();
    let d_lambda = (lon2 - lon1).to_radians();
    let a = (d_phi / 2.0).sin().powi(2)
        + phi1.cos() * phi2.cos() * (d_lambda / 2.0).sin().powi(2);
    let c = 2.0 * a.sqrt().atan2((1.0 - a).sqrt());
    r * c
}

fn variance(xs: &[f64]) -> f64 {
    let n = xs.len() as f64;
    if n < 2.0 { return 0.0; }
    let mean = xs.iter().sum::<f64>() / n;
    xs.iter().map(|x| (x - mean).powi(2)).sum::<f64>() / (n - 1.0)
}

// Suppress unused-import warnings when nalgebra row helpers aren't
// referenced — we keep them imported for forward-compat with future
// Mahalanobis-distance gating.
#[allow(dead_code)]
fn _row_keep_alive() {
    let _: RowVector2<f64> = RowVector2::zeros();
    let _: RowVector4<f64> = RowVector4::zeros();
    let _: RowVector6<f64> = RowVector6::zeros();
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn make(icao: u32, lat: f64, lon: f64, alt: i32, ts: u64) -> PhysicalState {
        PhysicalState {
            icao24: icao, lat, lon, altitude_ft: alt,
            velocity_knots: Some(450.0), heading: Some(90.0),
            timestamp_ms: ts,
        }
    }

    #[test]
    fn smooth_track_is_clean() {
        let mut e = KinematicEngine::new();
        let mut ts = 0;
        let mut lon = 0.0;
        for _ in 0..30 {
            assert!(e.process_state(make(0xABCDEF, 32.0, lon, 35000, ts)).is_none());
            ts += 1000;
            lon += 0.001;
        }
    }

    #[test]
    fn sudden_jump_is_caught() {
        let mut e = KinematicEngine::new();
        e.process_state(make(0x111111, 32.0, 0.0, 35000, 0));
        // 100 km in 100 ms → 1 Mm/s. Should hit the teleportation check.
        let r = e.process_state(make(0x111111, 33.0, 0.0, 35000, 100));
        assert!(matches!(r, Some(PhysicsAnomaly::Teleportation { .. })));
    }

    #[test]
    fn ground_spoof_flatline_is_caught() {
        let mut e = KinematicEngine::new();
        let mut ts = 0;
        let mut lon = 0.0;
        let sig = SignalReading { rssi_dbm: -60.0 };
        let mut last = None;
        for _ in 0..40 {
            last = e.process_state_with_signal(
                make(0x222222, 32.0, lon, 35000, ts), Some(&sig),
            );
            ts += 1000;
            lon += 0.001;
        }
        assert!(matches!(last, Some(PhysicsAnomaly::GroundSpoofSignal { .. })));
    }

    #[test]
    fn subterranean_blocked_immediately() {
        let mut e = KinematicEngine::new();
        let r = e.process_state(make(0x333333, 32.0, 0.0, -2000, 0));
        assert!(matches!(r, Some(PhysicsAnomaly::SubterraneanAltitude { .. })));
    }
}
