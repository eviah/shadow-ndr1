//! Hot-reload rule engine — swap rule sets at runtime with zero packet drop.
//!
//! ### Invariant
//!
//! At all times, every reader observes *some* valid `RuleSet` snapshot —
//! either the previous or the new one, never a torn intermediate. In-flight
//! evaluations against the previous snapshot complete safely; the engine
//! holds it alive until the last `Arc<RuleSet>` reference is dropped.
//!
//! ### Pattern
//!
//! `RwLock<Arc<RuleSet>>` is the simple correct shape:
//!
//! - **Reader**: `engine.snapshot()` acquires the read lock, clones the
//!   `Arc`, releases the lock. The actual rule evaluation happens against
//!   the owned `Arc` and never touches the lock again.
//! - **Writer**: `engine.replace(new)` acquires the write lock, swaps the
//!   inner `Arc`, releases. Old readers keep their pre-swap clone alive
//!   exactly as long as they need it.
//!
//! For 100k pkts/s with multi-million-rule sets the read-lock window is
//! a single `Arc::clone` — sub-100ns — so contention with the (slow,
//! human-driven) reload path is statistically nil. If profiling ever
//! shows the RwLock as a bottleneck, the same API drop-in upgrades to
//! `arc_swap::ArcSwap` for fully lock-free reads.
//!
//! ### Versioning
//!
//! Every successful `replace` bumps an `AtomicU64` version. Callers can
//! attach the version to alerts so SOC tooling knows which rule revision
//! produced a finding.

use crate::rule_jit::{PacketView, RuleSet};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};

pub struct HotReloadEngine {
    inner: RwLock<Arc<RuleSet>>,
    version: AtomicU64,
}

impl HotReloadEngine {
    pub fn new(initial: RuleSet) -> Self {
        HotReloadEngine {
            inner: RwLock::new(Arc::new(initial)),
            version: AtomicU64::new(1),
        }
    }

    /// Acquire a stable snapshot. Returns immediately; the snapshot stays
    /// valid for the lifetime of the returned `Arc`.
    pub fn snapshot(&self) -> Arc<RuleSet> {
        Arc::clone(&self.inner.read().expect("engine RwLock poisoned"))
    }

    /// Replace the active rule set. Returns the new version number.
    /// In-flight readers continue evaluating against the previous Arc;
    /// the previous Arc is dropped only when the last reader releases it.
    pub fn replace(&self, new: RuleSet) -> u64 {
        let new_arc = Arc::new(new);
        let mut guard = self.inner.write().expect("engine RwLock poisoned");
        *guard = new_arc;
        self.version.fetch_add(1, Ordering::AcqRel) + 1
    }

    pub fn version(&self) -> u64 {
        self.version.load(Ordering::Acquire)
    }

    /// Convenience: take a snapshot and evaluate one packet against it.
    /// For loops, prefer `snapshot()` once and reuse to avoid per-packet
    /// `Arc::clone`.
    pub fn evaluate(&self, pkt: &PacketView<'_>) -> Vec<u32> {
        self.snapshot().evaluate(pkt)
    }

    pub fn rule_count(&self) -> usize {
        self.snapshot().len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rule_jit::{Field, Predicate, RuleSet};
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
    use std::sync::Arc;
    use std::thread;
    use std::time::{Duration, Instant};

    fn pkt() -> PacketView<'static> {
        PacketView {
            proto: 6,
            src_port: 50000,
            dst_port: 80,
            src_ip: 0,
            dst_ip: 0,
            tcp_flags: 0,
            payload: b"GET /",
        }
    }

    fn rs_with(id: u32, port: u64) -> RuleSet {
        let mut rs = RuleSet::new();
        rs.add(id, &Predicate::field_eq(Field::DstPort, port));
        rs
    }

    #[test]
    fn initial_version_is_one() {
        let e = HotReloadEngine::new(rs_with(100, 80));
        assert_eq!(e.version(), 1);
    }

    #[test]
    fn replace_increments_version() {
        let e = HotReloadEngine::new(rs_with(100, 80));
        let v = e.replace(rs_with(200, 443));
        assert_eq!(v, 2);
        assert_eq!(e.version(), 2);
        let v = e.replace(rs_with(300, 22));
        assert_eq!(v, 3);
    }

    #[test]
    fn snapshot_after_replace_sees_new_rules() {
        let e = HotReloadEngine::new(rs_with(100, 80));
        let hits_before = e.evaluate(&pkt());
        assert_eq!(hits_before, vec![100]);

        e.replace(rs_with(200, 443));
        let hits_after = e.evaluate(&pkt());
        assert_eq!(hits_after, Vec::<u32>::new()); // pkt has dst_port=80, not 443
    }

    #[test]
    fn in_flight_snapshot_survives_replace() {
        let e = HotReloadEngine::new(rs_with(100, 80));
        // Reader takes snapshot — but doesn't evaluate yet.
        let snap = e.snapshot();
        assert_eq!(Arc::strong_count(&snap), 2); // snap + engine.inner

        // Writer replaces.
        e.replace(rs_with(200, 443));

        // Reader's snapshot is still valid and observes the OLD rule.
        let hits = snap.evaluate(&pkt());
        assert_eq!(hits, vec![100]);

        // Engine no longer references the old snapshot — only `snap` does.
        assert_eq!(Arc::strong_count(&snap), 1);
    }

    #[test]
    fn concurrent_evaluators_and_replacer_no_torn_reads() {
        let engine = Arc::new(HotReloadEngine::new(rs_with(100, 80)));
        let stop = Arc::new(AtomicBool::new(false));
        let evaluations = Arc::new(AtomicU64::new(0));
        let replacements = Arc::new(AtomicU64::new(0));

        let mut workers = Vec::new();
        for _ in 0..4 {
            let engine = Arc::clone(&engine);
            let stop = Arc::clone(&stop);
            let evaluations = Arc::clone(&evaluations);
            workers.push(thread::spawn(move || {
                while !stop.load(Ordering::Relaxed) {
                    // The set of valid hit-id values across all rule
                    // versions: {[], [100], [200], [300], [400]}. A torn
                    // read would yield something else (impossible IDs,
                    // panic, etc.), which would surface as test failure.
                    let hits = engine.evaluate(&pkt());
                    for id in &hits {
                        assert!(matches!(id, 100 | 200 | 300 | 400));
                    }
                    evaluations.fetch_add(1, Ordering::Relaxed);
                }
            }));
        }

        let writer = {
            let engine = Arc::clone(&engine);
            let stop = Arc::clone(&stop);
            let replacements = Arc::clone(&replacements);
            thread::spawn(move || {
                let mut id = 100u32;
                while !stop.load(Ordering::Relaxed) {
                    id = ((id - 100 + 100) % 400) + 100; // cycle 100→200→300→400
                    engine.replace(rs_with(id, 80));
                    replacements.fetch_add(1, Ordering::Relaxed);
                    thread::sleep(Duration::from_micros(50));
                }
            })
        };

        let deadline = Instant::now() + Duration::from_millis(200);
        while Instant::now() < deadline {
            thread::sleep(Duration::from_millis(10));
        }
        stop.store(true, Ordering::Relaxed);

        for w in workers {
            w.join().unwrap();
        }
        writer.join().unwrap();

        assert!(evaluations.load(Ordering::Relaxed) > 100);
        assert!(replacements.load(Ordering::Relaxed) > 5);
    }

    #[test]
    fn snapshot_is_cheap_per_call() {
        let e = HotReloadEngine::new(rs_with(100, 80));
        // 10k snapshot calls in well under a second on any modern box.
        let start = Instant::now();
        for _ in 0..10_000 {
            let _ = e.snapshot();
        }
        let elapsed = start.elapsed();
        assert!(elapsed < Duration::from_millis(500), "10k snapshots took {:?}", elapsed);
    }

    #[test]
    fn rule_count_reflects_current_snapshot() {
        let mut rs = RuleSet::new();
        rs.add(1, &Predicate::AlwaysTrue);
        rs.add(2, &Predicate::AlwaysTrue);
        rs.add(3, &Predicate::AlwaysTrue);
        let e = HotReloadEngine::new(rs);
        assert_eq!(e.rule_count(), 3);

        let mut new_rs = RuleSet::new();
        new_rs.add(99, &Predicate::AlwaysFalse);
        e.replace(new_rs);
        assert_eq!(e.rule_count(), 1);
    }
}
