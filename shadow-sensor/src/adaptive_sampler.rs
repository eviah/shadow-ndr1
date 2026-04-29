//! Adaptive packet sampling under backpressure (PSI-style).
//!
//! Linux's PSI (Pressure Stall Information) tracks how much wall time
//! threads spend stalled on a resource. Shadow NDR's analogue is the
//! drop-ratio: when the capture ring runs out of buffer faster than the
//! analyzer drains it, we'd rather *deepen the inspection* on a smaller
//! sample of packets than apply shallow inspection to all of them and
//! miss everything.
//!
//! ### Decision shape
//!
//! `should_sample(hash)` is a stateless lookup against the current target
//! rate: `(hash % 1_000_000) < rate * 1_000_000`. Two analyzers seeing
//! the same packet make the same decision, so flow-affinity is preserved
//! across replica sensors.
//!
//! `record_pressure(drops, total, now_ns)` is called by the capture
//! reporter once per period (typically 1s). It pushes one drop-ratio
//! sample into a rolling window, recomputes the EMA, and adjusts the
//! sample rate using:
//!
//!   * avg > target           → multiplicative decrease (factor `1 - α`)
//!   * avg < target / 2       → multiplicative increase (factor `1 + α/2`)
//!   * else                   → hold
//!
//! Multiplicative decrease + additive recovery is the AIMD-style law
//! that gives stable convergence under bursty drops; pure additive
//! recovery prevents oscillation around the target.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;

#[derive(Clone, Debug)]
pub struct SamplerConfig {
    pub target_drop_ratio: f64,
    pub min_rate: f64,
    pub max_rate: f64,
    pub aggression: f64,
    pub window: usize,
}

impl Default for SamplerConfig {
    fn default() -> Self {
        SamplerConfig {
            target_drop_ratio: 0.01, // 1% drops tolerated
            min_rate: 0.01,          // never below 1%
            max_rate: 1.0,
            aggression: 0.25,
            window: 16,
        }
    }
}

pub struct AdaptiveSampler {
    config: SamplerConfig,
    /// Sample rate as parts-per-million. We use ppm + AtomicU64 instead
    /// of f64 so `should_sample` is fully lock-free.
    rate_ppm: AtomicU64,
    state: Mutex<SamplerState>,
}

struct SamplerState {
    pressure_window: VecDeque<f64>,
    last_drops: u64,
    last_total: u64,
    last_decision_ns: u64,
    decisions_made: u64,
}

impl AdaptiveSampler {
    pub fn new(config: SamplerConfig) -> Self {
        assert!(config.min_rate >= 0.0 && config.min_rate <= config.max_rate);
        assert!(config.max_rate <= 1.0);
        assert!(config.aggression > 0.0 && config.aggression < 1.0);
        assert!(config.window > 0);
        let initial_rate_ppm = (config.max_rate * 1_000_000.0) as u64;
        AdaptiveSampler {
            config,
            rate_ppm: AtomicU64::new(initial_rate_ppm),
            state: Mutex::new(SamplerState {
                pressure_window: VecDeque::new(),
                last_drops: 0,
                last_total: 0,
                last_decision_ns: 0,
                decisions_made: 0,
            }),
        }
    }

    /// Lock-free sample decision. `hash` should be a stable per-packet or
    /// per-flow hash so the same input produces the same decision across
    /// peer sensors.
    pub fn should_sample(&self, hash: u64) -> bool {
        let cutoff = self.rate_ppm.load(Ordering::Relaxed);
        (hash % 1_000_000) < cutoff
    }

    pub fn current_rate(&self) -> f64 {
        (self.rate_ppm.load(Ordering::Relaxed) as f64) / 1_000_000.0
    }

    pub fn current_rate_ppm(&self) -> u64 {
        self.rate_ppm.load(Ordering::Relaxed)
    }

    pub fn decisions_made(&self) -> u64 {
        self.state.lock().unwrap().decisions_made
    }

    /// Ingest one period's drop telemetry. Updates the active sample rate.
    /// `drops` and `total` are cumulative counters since sensor start;
    /// the sampler diffs against the last call automatically.
    pub fn record_pressure(&self, drops: u64, total: u64, now_ns: u64) {
        let mut st = self.state.lock().unwrap();
        let dd = drops.saturating_sub(st.last_drops);
        let dt = total.saturating_sub(st.last_total);
        st.last_drops = drops;
        st.last_total = total;
        st.last_decision_ns = now_ns;
        st.decisions_made += 1;

        let pressure = if dt == 0 { 0.0 } else { (dd as f64) / (dt as f64) };
        st.pressure_window.push_back(pressure.clamp(0.0, 1.0));
        while st.pressure_window.len() > self.config.window {
            st.pressure_window.pop_front();
        }
        let avg: f64 = if st.pressure_window.is_empty() {
            0.0
        } else {
            st.pressure_window.iter().sum::<f64>() / (st.pressure_window.len() as f64)
        };

        let cur_rate = (self.rate_ppm.load(Ordering::Relaxed) as f64) / 1_000_000.0;
        let new_rate = if avg > self.config.target_drop_ratio {
            // Multiplicative decrease.
            cur_rate * (1.0 - self.config.aggression)
        } else if avg < self.config.target_drop_ratio / 2.0 {
            // Gentle additive recovery.
            (cur_rate + self.config.aggression * 0.1).min(self.config.max_rate)
        } else {
            cur_rate
        };
        let new_rate = new_rate.clamp(self.config.min_rate, self.config.max_rate);
        self.rate_ppm
            .store((new_rate * 1_000_000.0) as u64, Ordering::Relaxed);
    }

    /// Reset to the configured max rate (e.g., on shift change or operator
    /// override).
    pub fn reset_to_max(&self) {
        let ppm = (self.config.max_rate * 1_000_000.0) as u64;
        self.rate_ppm.store(ppm, Ordering::Relaxed);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::thread;

    fn cfg() -> SamplerConfig {
        SamplerConfig {
            target_drop_ratio: 0.01,
            min_rate: 0.01,
            max_rate: 1.0,
            aggression: 0.25,
            window: 8,
        }
    }

    #[test]
    fn starts_at_max_rate() {
        let s = AdaptiveSampler::new(cfg());
        assert!((s.current_rate() - 1.0).abs() < 1e-9);
        assert!(s.should_sample(0));
        assert!(s.should_sample(999_999));
    }

    #[test]
    fn high_drop_pressure_lowers_rate() {
        let s = AdaptiveSampler::new(cfg());
        // Simulate sustained 5% drop rate (5x target).
        let mut drops = 0u64;
        let mut total = 0u64;
        let initial_rate = s.current_rate();
        for tick in 1..=10u64 {
            total += 1_000_000;
            drops += 50_000; // 5% drops
            s.record_pressure(drops, total, tick * 1_000_000_000);
        }
        let after = s.current_rate();
        assert!(after < initial_rate, "rate did not decrease: {after}");
        assert!(after < 0.5, "rate should be aggressively lowered, got {after}");
    }

    #[test]
    fn rate_recovers_when_pressure_clears() {
        let s = AdaptiveSampler::new(cfg());
        let mut drops = 0u64;
        let mut total = 0u64;
        // Drive rate down with high pressure.
        for tick in 1..=15u64 {
            total += 1_000_000;
            drops += 50_000;
            s.record_pressure(drops, total, tick * 1_000_000_000);
        }
        let dipped = s.current_rate();
        assert!(dipped < 0.5);

        // Now clean: zero drops for many ticks.
        for tick in 16..=200u64 {
            total += 1_000_000;
            // drops unchanged → 0 new drops
            s.record_pressure(drops, total, tick * 1_000_000_000);
        }
        let recovered = s.current_rate();
        assert!(
            recovered > dipped + 0.05,
            "expected recovery, dipped={dipped} recovered={recovered}"
        );
    }

    #[test]
    fn rate_clamped_to_min() {
        let mut config = cfg();
        config.min_rate = 0.05;
        let s = AdaptiveSampler::new(config);
        let mut drops = 0u64;
        let mut total = 0u64;
        // Hammer with extreme pressure for many cycles.
        for tick in 1..=50u64 {
            total += 1_000_000;
            drops += 500_000; // 50% drops
            s.record_pressure(drops, total, tick * 1_000_000_000);
        }
        assert!(s.current_rate() >= 0.05 - 1e-6);
        assert!(s.current_rate() <= 0.05 + 0.01); // shouldn't undershoot meaningfully
    }

    #[test]
    fn rate_clamped_to_max() {
        let mut config = cfg();
        config.max_rate = 0.5;
        let s = AdaptiveSampler::new(config);
        assert!((s.current_rate() - 0.5).abs() < 1e-9);
        // Even with no pressure, can't exceed max.
        for tick in 1..=200u64 {
            s.record_pressure(0, 1_000_000 * tick, tick * 1_000_000_000);
        }
        assert!(s.current_rate() <= 0.5 + 1e-6);
    }

    #[test]
    fn should_sample_distribution_matches_rate() {
        let s = AdaptiveSampler::new(cfg());
        // Drive rate to ~0.5 by simulating sustained 2% drops (2x target).
        let mut drops = 0u64;
        let mut total = 0u64;
        // Hand-set rate via a few cycles. Easier: use a probe of
        // should_sample with known rate using reset+set_rate.
        // Instead: directly verify that at rate=1.0, every hash samples;
        // at rate=0.0 (well, min=0.01 so 1%), nearly none.
        let _ = (drops, total);
        let mut hits = 0;
        for h in 0..10_000u64 {
            if s.should_sample(h * 7919) {
                hits += 1;
            }
        }
        assert_eq!(hits, 10_000); // rate=1.0

        // Now lower rate aggressively.
        for tick in 1..=50u64 {
            s.record_pressure(50_000 * tick, 1_000_000 * tick, tick * 1_000_000_000);
        }
        let rate = s.current_rate();
        let mut hits = 0;
        for h in 0..10_000u64 {
            if s.should_sample(h * 7919) {
                hits += 1;
            }
        }
        let observed = hits as f64 / 10_000.0;
        // observed should be within 5% of target rate.
        assert!(
            (observed - rate).abs() < 0.05,
            "observed={observed} target={rate}"
        );
    }

    #[test]
    fn decisions_counter_advances() {
        let s = AdaptiveSampler::new(cfg());
        assert_eq!(s.decisions_made(), 0);
        s.record_pressure(0, 1000, 1_000_000_000);
        s.record_pressure(0, 2000, 2_000_000_000);
        assert_eq!(s.decisions_made(), 2);
    }

    #[test]
    fn reset_to_max_restores_rate() {
        let s = AdaptiveSampler::new(cfg());
        for tick in 1..=20u64 {
            s.record_pressure(50_000 * tick, 1_000_000 * tick, tick * 1_000_000_000);
        }
        assert!(s.current_rate() < 0.5);
        s.reset_to_max();
        assert!((s.current_rate() - 1.0).abs() < 1e-9);
    }

    #[test]
    fn concurrent_record_and_sample_is_safe() {
        let s = Arc::new(AdaptiveSampler::new(cfg()));
        let producers = (0..2)
            .map(|p| {
                let s = Arc::clone(&s);
                thread::spawn(move || {
                    for tick in 1..=200u64 {
                        let drops = (tick * (1 + p) * 50_000) as u64;
                        let total = tick * 1_000_000;
                        s.record_pressure(drops, total, tick * 1_000_000_000);
                    }
                })
            })
            .collect::<Vec<_>>();
        let consumers = (0..4)
            .map(|_| {
                let s = Arc::clone(&s);
                thread::spawn(move || {
                    let mut hits = 0u64;
                    for h in 0..10_000u64 {
                        if s.should_sample(h * 31337) {
                            hits += 1;
                        }
                    }
                    hits
                })
            })
            .collect::<Vec<_>>();
        for p in producers {
            p.join().unwrap();
        }
        for c in consumers {
            let _ = c.join().unwrap();
        }
        // Final rate must be within configured bounds.
        let rate = s.current_rate();
        assert!(rate >= cfg().min_rate && rate <= cfg().max_rate);
    }

    #[test]
    fn window_smooths_single_spike() {
        let s = AdaptiveSampler::new(cfg());
        // Many clean ticks then one big spike — window-averaging should
        // damp the response so rate doesn't crater.
        for tick in 1..=20u64 {
            s.record_pressure(0, 1_000_000 * tick, tick * 1_000_000_000);
        }
        let pre = s.current_rate();
        // One spike: 30% drops in this period only.
        s.record_pressure(300_000, 1_000_000 * 21, 21 * 1_000_000_000);
        let post = s.current_rate();
        // Window of 8 means avg pressure ≈ 30%/8 = 3.75% — above target,
        // so rate dips, but not catastrophically.
        assert!(post < pre, "pre={pre} post={post}");
        assert!(post > 0.5, "single spike shouldn't crater rate, got {post}");
    }
}
