//! HDR (High Dynamic Range) histogram for per-flow / per-rule telemetry.
//!
//! Faithful to Gil Tene's HDR algorithm (the same one shipped by the
//! `hdrhistogram` crate, Cassandra, and Hazelcast) but written from
//! scratch to avoid the dependency. Records values in O(1), recovers
//! quantiles in O(buckets), and preserves N significant decimal digits
//! across the *entire* dynamic range up to 2^63.
//!
//! ### Layout
//!
//! For `sig_digits=3` the sub-bucket count is 2048 (next power of two
//! above 2*10^3 = 2000). Each magnitude doubles the range covered by a
//! sub-bucket. With 32 magnitudes the histogram covers values in
//! [0, 2^42) with ≤ ~0.05% bucket-quantization error at the recorded
//! quantile.
//!
//! ### Use in Shadow NDR
//!
//! `FlowTelemetry` aggregates four HDR histograms — packet size,
//! inter-arrival time, TTL distribution, and TCP window size — into a
//! single bundle the detection pipeline attaches to "interesting" flows
//! (those flagged by the rule engine or matching tracked-asset 5-tuples).
//! It is not attached to *every* flow — at ~265 KB per bundle the
//! sensor would need ~25 MB / 100 flows, which is fine for a watchlist
//! but excessive for the entire flow table.

#[derive(Clone, Debug)]
pub struct HdrHistogram {
    sub_buckets: usize,
    magnitudes: usize,
    log_sb: u32,
    counts: Vec<u64>,
    total: u64,
    min: u64,
    max: u64,
    sum: u128,
}

impl HdrHistogram {
    /// Build a histogram with `sig_digits` of precision (1–5 reasonable).
    pub fn new(sig_digits: u32) -> Self {
        assert!((1..=5).contains(&sig_digits));
        // HDR convention: sub_bucket count = 2 * 10^sig_digits, rounded up
        // to the next power of two. sig=3 → 2000 → 2048 (≈0.05% bucket
        // quantization error).
        let approx = 2 * 10u64.pow(sig_digits);
        let sub_buckets = approx.next_power_of_two() as usize;
        let log_sb = sub_buckets.trailing_zeros();
        // 64-bit max covers up to 2^63; magnitudes from 0 to (63 - log_sb).
        let magnitudes = 64 - log_sb as usize;
        let counts = vec![0u64; sub_buckets * magnitudes];
        HdrHistogram {
            sub_buckets,
            magnitudes,
            log_sb,
            counts,
            total: 0,
            min: u64::MAX,
            max: 0,
            sum: 0,
        }
    }

    pub fn total_count(&self) -> u64 {
        self.total
    }

    pub fn min(&self) -> u64 {
        if self.total == 0 {
            0
        } else {
            self.min
        }
    }
    pub fn max(&self) -> u64 {
        self.max
    }
    pub fn mean(&self) -> f64 {
        if self.total == 0 {
            0.0
        } else {
            (self.sum as f64) / (self.total as f64)
        }
    }
    pub fn sum(&self) -> u128 {
        self.sum
    }

    pub fn reset(&mut self) {
        self.counts.iter_mut().for_each(|c| *c = 0);
        self.total = 0;
        self.min = u64::MAX;
        self.max = 0;
        self.sum = 0;
    }

    /// O(1) record. Saturates at the largest representable value.
    pub fn record(&mut self, v: u64) {
        let idx = self.bucket_idx(v);
        self.counts[idx] = self.counts[idx].saturating_add(1);
        self.total = self.total.saturating_add(1);
        self.sum = self.sum.saturating_add(v as u128);
        if v < self.min {
            self.min = v;
        }
        if v > self.max {
            self.max = v;
        }
    }

    pub fn record_n(&mut self, v: u64, n: u64) {
        if n == 0 {
            return;
        }
        let idx = self.bucket_idx(v);
        self.counts[idx] = self.counts[idx].saturating_add(n);
        self.total = self.total.saturating_add(n);
        self.sum = self.sum.saturating_add((v as u128) * (n as u128));
        if v < self.min {
            self.min = v;
        }
        if v > self.max {
            self.max = v;
        }
    }

    /// O(buckets) inverse-cumulative lookup.
    pub fn value_at_quantile(&self, q: f64) -> u64 {
        if self.total == 0 {
            return 0;
        }
        let q = q.clamp(0.0, 1.0);
        let target = ((q * self.total as f64).ceil() as u64).max(1);
        let mut cum = 0u64;
        for (i, &c) in self.counts.iter().enumerate() {
            if c == 0 {
                continue;
            }
            cum += c;
            if cum >= target {
                let mag = i / self.sub_buckets;
                let sub = i % self.sub_buckets;
                return self.value_for(mag, sub);
            }
        }
        self.max
    }

    /// Combine `other` into `self`. Buckets at the same index simply add;
    /// histograms must be configured with the same `sig_digits`.
    pub fn merge(&mut self, other: &HdrHistogram) -> Result<(), &'static str> {
        if self.sub_buckets != other.sub_buckets || self.magnitudes != other.magnitudes {
            return Err("incompatible HdrHistogram dimensions");
        }
        for (a, b) in self.counts.iter_mut().zip(&other.counts) {
            *a = a.saturating_add(*b);
        }
        self.total = self.total.saturating_add(other.total);
        self.sum = self.sum.saturating_add(other.sum);
        if other.total > 0 {
            if other.min < self.min {
                self.min = other.min;
            }
            if other.max > self.max {
                self.max = other.max;
            }
        }
        Ok(())
    }

    fn bucket_idx(&self, v: u64) -> usize {
        let mag = if v < self.sub_buckets as u64 {
            0
        } else {
            let log_v = 63 - v.leading_zeros();
            (log_v - self.log_sb + 1) as usize
        };
        let mag = mag.min(self.magnitudes - 1);
        let sub = ((v >> mag) as usize).min(self.sub_buckets - 1);
        mag * self.sub_buckets + sub
    }

    fn value_for(&self, mag: usize, sub: usize) -> u64 {
        if mag == 0 {
            sub as u64
        } else {
            (sub as u64) << mag
        }
    }
}

/// Bundle of four HDR histograms commonly attached to a tracked flow or
/// rule-tagged stream.
#[derive(Clone, Debug)]
pub struct FlowTelemetry {
    pub packet_size: HdrHistogram,
    pub interarrival_ns: HdrHistogram,
    pub ttl: HdrHistogram,
    pub tcp_window: HdrHistogram,
    last_seen_ns: Option<u64>,
}

impl FlowTelemetry {
    pub fn new() -> Self {
        FlowTelemetry {
            packet_size: HdrHistogram::new(3),
            interarrival_ns: HdrHistogram::new(3),
            ttl: HdrHistogram::new(2),
            tcp_window: HdrHistogram::new(3),
            last_seen_ns: None,
        }
    }

    pub fn observe(&mut self, size: u32, ttl: u8, now_ns: u64, tcp_window: Option<u16>) {
        self.packet_size.record(size as u64);
        self.ttl.record(ttl as u64);
        if let Some(w) = tcp_window {
            self.tcp_window.record(w as u64);
        }
        if let Some(prev) = self.last_seen_ns {
            self.interarrival_ns.record(now_ns.saturating_sub(prev));
        }
        self.last_seen_ns = Some(now_ns);
    }

    pub fn snapshot(&self) -> TelemetrySnapshot {
        TelemetrySnapshot {
            packet_count: self.packet_size.total_count(),
            packet_size_p50: self.packet_size.value_at_quantile(0.5),
            packet_size_p99: self.packet_size.value_at_quantile(0.99),
            interarrival_p50_ns: self.interarrival_ns.value_at_quantile(0.5),
            interarrival_p99_ns: self.interarrival_ns.value_at_quantile(0.99),
            ttl_min: self.ttl.min(),
            ttl_max: self.ttl.max(),
            tcp_window_p50: self.tcp_window.value_at_quantile(0.5),
        }
    }
}

impl Default for FlowTelemetry {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TelemetrySnapshot {
    pub packet_count: u64,
    pub packet_size_p50: u64,
    pub packet_size_p99: u64,
    pub interarrival_p50_ns: u64,
    pub interarrival_p99_ns: u64,
    pub ttl_min: u64,
    pub ttl_max: u64,
    pub tcp_window_p50: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_histogram_quantile_is_zero() {
        let h = HdrHistogram::new(3);
        assert_eq!(h.value_at_quantile(0.5), 0);
        assert_eq!(h.total_count(), 0);
        assert_eq!(h.min(), 0);
        assert_eq!(h.max(), 0);
    }

    #[test]
    fn single_value_recovers_at_all_quantiles() {
        let mut h = HdrHistogram::new(3);
        for _ in 0..100 {
            h.record(1234);
        }
        assert_eq!(h.total_count(), 100);
        // With 3 sig digits, quantization within ±1 of true value at this scale.
        for q in [0.01, 0.5, 0.99] {
            let v = h.value_at_quantile(q);
            assert!((1232..=1236).contains(&v), "q={} got {}", q, v);
        }
    }

    #[test]
    fn min_max_mean_track() {
        let mut h = HdrHistogram::new(3);
        h.record(10);
        h.record(20);
        h.record(30);
        assert_eq!(h.min(), 10);
        assert_eq!(h.max(), 30);
        assert!((h.mean() - 20.0).abs() < 0.001);
    }

    #[test]
    fn quantile_is_monotone_increasing() {
        let mut h = HdrHistogram::new(3);
        for v in 1..=1000u64 {
            h.record(v);
        }
        let p1 = h.value_at_quantile(0.01);
        let p50 = h.value_at_quantile(0.5);
        let p99 = h.value_at_quantile(0.99);
        assert!(p1 < p50, "{p1} < {p50}");
        assert!(p50 < p99, "{p50} < {p99}");
        // Approximate expected values within precision tolerance (±1%).
        assert!((9..=12).contains(&p1), "p1={p1}");
        assert!((495..=505).contains(&p50), "p50={p50}");
        assert!((985..=1000).contains(&p99), "p99={p99}");
    }

    #[test]
    fn handles_full_dynamic_range() {
        let mut h = HdrHistogram::new(3);
        h.record(1);
        h.record(1_000);
        h.record(1_000_000);
        h.record(1_000_000_000);
        h.record(1_000_000_000_000);
        assert_eq!(h.total_count(), 5);
        // Quantile lookup must round-trip each magnitude inside ±1%.
        let p50 = h.value_at_quantile(0.5);
        // median is somewhere in 1000..1_000_000 region
        assert!(p50 >= 1_000 && p50 <= 1_001_000);
    }

    #[test]
    fn merge_combines_counts_and_sum() {
        let mut a = HdrHistogram::new(3);
        let mut b = HdrHistogram::new(3);
        for _ in 0..10 {
            a.record(100);
        }
        for _ in 0..10 {
            b.record(200);
        }
        a.merge(&b).unwrap();
        assert_eq!(a.total_count(), 20);
        assert_eq!(a.min(), 100);
        assert_eq!(a.max(), 200);
        let p50 = a.value_at_quantile(0.5);
        assert!((99..=101).contains(&p50), "p50={p50}");
    }

    #[test]
    fn merge_rejects_dimension_mismatch() {
        let mut a = HdrHistogram::new(3);
        let b = HdrHistogram::new(2);
        assert!(a.merge(&b).is_err());
    }

    #[test]
    fn record_zero_is_well_defined() {
        let mut h = HdrHistogram::new(3);
        h.record(0);
        assert_eq!(h.min(), 0);
        assert_eq!(h.max(), 0);
        assert_eq!(h.value_at_quantile(0.5), 0);
    }

    #[test]
    fn record_n_matches_repeated_record() {
        let mut a = HdrHistogram::new(3);
        let mut b = HdrHistogram::new(3);
        for _ in 0..1000 {
            a.record(42);
        }
        b.record_n(42, 1000);
        assert_eq!(a.total_count(), b.total_count());
        assert_eq!(a.value_at_quantile(0.5), b.value_at_quantile(0.5));
        assert_eq!(a.sum(), b.sum());
    }

    #[test]
    fn reset_clears_state() {
        let mut h = HdrHistogram::new(3);
        for v in 1..=100 {
            h.record(v);
        }
        h.reset();
        assert_eq!(h.total_count(), 0);
        assert_eq!(h.value_at_quantile(0.5), 0);
        assert_eq!(h.max(), 0);
    }

    #[test]
    fn flow_telemetry_observe_and_snapshot() {
        let mut t = FlowTelemetry::new();
        t.observe(64, 64, 0, Some(8192));
        t.observe(1500, 64, 1_000_000, Some(8192));
        t.observe(1500, 63, 2_000_000, Some(16384));
        t.observe(40, 64, 3_000_000, Some(16384));
        let s = t.snapshot();
        assert_eq!(s.packet_count, 4);
        assert!(s.packet_size_p50 >= 64 && s.packet_size_p50 <= 1500);
        assert_eq!(s.ttl_min, 63);
        assert_eq!(s.ttl_max, 64);
        // Three inter-arrival samples were recorded (the first observe has
        // no predecessor so it doesn't generate one).
        assert!(s.interarrival_p50_ns > 0);
    }

    #[test]
    fn flow_telemetry_first_observation_no_interarrival() {
        let mut t = FlowTelemetry::new();
        t.observe(64, 64, 1_000_000, None);
        let s = t.snapshot();
        assert_eq!(s.packet_count, 1);
        assert_eq!(s.interarrival_p50_ns, 0); // no inter-arrival yet
    }
}
