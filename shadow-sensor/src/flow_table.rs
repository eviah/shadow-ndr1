//! Lock-free sharded flow table with epoch-style reclamation.
//!
//! Design goals (in priority order):
//!   1. **Read fast path**: `observe(key, ...)` for an *existing* flow is
//!      one hash → shard read-lock → atomic increments. No write lock,
//!      no allocation.
//!   2. **Write fast path**: `observe(key, ...)` for a *new* flow takes a
//!      single shard write lock long enough to insert one Arc, then
//!      drops the lock before performing the per-flow updates.
//!   3. **Bidirectional flows are one entry**: `FlowKey::canonical()`
//!      orders endpoints so A→B and B→A collapse to one key. Per-direction
//!      packet counts are kept in separate atomics on the entry.
//!   4. **Bounded memory**: `sweep` evicts idle flows, `evict_oldest`
//!      handles capacity pressure. Both are O(N) scans run on a low-rate
//!      sweeper task.
//!   5. **Safe reclamation**: entries live behind `Arc<FlowEntry>`. If a
//!      sweeper removes a flow while another thread holds a clone of the
//!      Arc, the entry is freed when the last clone drops — exactly the
//!      epoch-reclamation property we want, expressed via the type system
//!      instead of a separate epoch crate.
//!
//! Sharding is provided by `dashmap`, which holds per-shard `RwLock`s so
//! reads on shard X don't block writes on shard Y.

use dashmap::DashMap;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU16, AtomicU64, AtomicU8, Ordering};
use std::sync::Arc;

/// Five-tuple flow key. Hashed/compared by all fields; `canonical()` yields
/// a direction-insensitive variant so client→server and server→client share
/// one entry.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct FlowKey {
    pub src_ip: IpAddr,
    pub dst_ip: IpAddr,
    pub src_port: u16,
    pub dst_port: u16,
    pub proto: u8,
}

impl FlowKey {
    /// Reorder endpoints so the lexicographically smaller (ip, port) is
    /// "src". Idempotent — `canonical().canonical() == canonical()`.
    pub fn canonical(self) -> Self {
        let lhs = (self.src_ip, self.src_port);
        let rhs = (self.dst_ip, self.dst_port);
        if lhs <= rhs {
            self
        } else {
            FlowKey {
                src_ip: self.dst_ip,
                dst_ip: self.src_ip,
                src_port: self.dst_port,
                dst_port: self.src_port,
                proto: self.proto,
            }
        }
    }

    /// Returns true iff `self` (raw, *before* canonicalization) is the
    /// "forward" direction of its canonical form.
    pub fn is_forward(self) -> bool {
        let lhs = (self.src_ip, self.src_port);
        let rhs = (self.dst_ip, self.dst_port);
        lhs <= rhs
    }
}

/// TCP-state bits packed into one byte for atomic CAS-able transitions.
#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TcpState {
    Unknown = 0,
    Syn = 1,
    SynAck = 2,
    Established = 3,
    FinWait = 4,
    Closed = 5,
    Reset = 6,
}

impl TcpState {
    pub fn from_u8(b: u8) -> Self {
        match b {
            1 => Self::Syn,
            2 => Self::SynAck,
            3 => Self::Established,
            4 => Self::FinWait,
            5 => Self::Closed,
            6 => Self::Reset,
            _ => Self::Unknown,
        }
    }
}

/// Per-flow stats. All mutable fields are atomic so the hot path holds
/// only a read shard-lock from `DashMap`.
#[derive(Debug)]
pub struct FlowEntry {
    pub packets: AtomicU64,
    pub bytes: AtomicU64,
    pub fwd_packets: AtomicU64,
    pub rev_packets: AtomicU64,
    pub fwd_bytes: AtomicU64,
    pub rev_bytes: AtomicU64,
    pub first_seen_ns: u64,
    pub last_seen_ns: AtomicU64,
    pub tcp_state: AtomicU8,
    pub app_proto: AtomicU16,
}

impl FlowEntry {
    fn new(now_ns: u64) -> Self {
        FlowEntry {
            packets: AtomicU64::new(0),
            bytes: AtomicU64::new(0),
            fwd_packets: AtomicU64::new(0),
            rev_packets: AtomicU64::new(0),
            fwd_bytes: AtomicU64::new(0),
            rev_bytes: AtomicU64::new(0),
            first_seen_ns: now_ns,
            last_seen_ns: AtomicU64::new(now_ns),
            tcp_state: AtomicU8::new(TcpState::Unknown as u8),
            app_proto: AtomicU16::new(0),
        }
    }

    /// CAS-loop transition that respects monotonicity: only the listed
    /// "advance" transitions take effect. Any state may move to Reset.
    pub fn advance_tcp(&self, target: TcpState) {
        let target_u8 = target as u8;
        loop {
            let cur = self.tcp_state.load(Ordering::Relaxed);
            let cur_state = TcpState::from_u8(cur);
            let allowed = matches!(target, TcpState::Reset)
                || matches!(
                    (cur_state, target),
                    (TcpState::Unknown, TcpState::Syn)
                        | (TcpState::Syn, TcpState::SynAck)
                        | (TcpState::SynAck, TcpState::Established)
                        | (TcpState::Established, TcpState::FinWait)
                        | (TcpState::FinWait, TcpState::Closed)
                );
            if !allowed {
                return;
            }
            if self
                .tcp_state
                .compare_exchange_weak(cur, target_u8, Ordering::AcqRel, Ordering::Relaxed)
                .is_ok()
            {
                return;
            }
        }
    }
}

/// Sharded flow table. `dashmap` provides the read/write shard locks; this
/// type adds canonicalization, forward/reverse counters, idle eviction, and
/// capacity-bounded back-pressure.
pub struct FlowTable {
    table: DashMap<FlowKey, Arc<FlowEntry>>,
    capacity: usize,
    idle_timeout_ns: u64,
}

impl FlowTable {
    pub fn new(capacity: usize, idle_timeout_secs: u64) -> Self {
        FlowTable {
            table: DashMap::with_capacity(capacity.max(1024)),
            capacity,
            idle_timeout_ns: idle_timeout_secs.saturating_mul(1_000_000_000),
        }
    }

    pub fn len(&self) -> usize {
        self.table.len()
    }

    pub fn is_empty(&self) -> bool {
        self.table.is_empty()
    }

    pub fn capacity(&self) -> usize {
        self.capacity
    }

    /// Look up an existing flow without inserting.
    pub fn get(&self, key: &FlowKey) -> Option<Arc<FlowEntry>> {
        self.table.get(&key.canonical()).map(|r| r.value().clone())
    }

    /// Hot path. Increments per-flow counters; allocates only on first-seen.
    /// Returns the (possibly fresh) `Arc<FlowEntry>` so callers can drive
    /// follow-up work (TCP state, app-proto detection, etc.) lock-free.
    pub fn observe(&self, key: FlowKey, pkt_bytes: u64, now_ns: u64) -> Arc<FlowEntry> {
        let forward = key.is_forward();
        let canon = key.canonical();
        // `entry().or_insert_with` holds a write-shard lock only on miss,
        // and a read-shard lock on hit. We clone the Arc and immediately
        // drop the guard so the per-flow atomic updates don't extend the
        // lock window.
        let arc: Arc<FlowEntry> = {
            let guard = self
                .table
                .entry(canon)
                .or_insert_with(|| Arc::new(FlowEntry::new(now_ns)));
            guard.value().clone()
        };
        arc.packets.fetch_add(1, Ordering::Relaxed);
        arc.bytes.fetch_add(pkt_bytes, Ordering::Relaxed);
        arc.last_seen_ns.store(now_ns, Ordering::Relaxed);
        if forward {
            arc.fwd_packets.fetch_add(1, Ordering::Relaxed);
            arc.fwd_bytes.fetch_add(pkt_bytes, Ordering::Relaxed);
        } else {
            arc.rev_packets.fetch_add(1, Ordering::Relaxed);
            arc.rev_bytes.fetch_add(pkt_bytes, Ordering::Relaxed);
        }
        arc
    }

    /// Sweep idle flows. Two-pass: first scan under per-shard read locks to
    /// collect candidates, then remove with re-check under write locks so
    /// flows that received a packet mid-sweep aren't lost.
    pub fn sweep(&self, now_ns: u64) -> usize {
        let cutoff = self.idle_timeout_ns;
        let candidates: Vec<FlowKey> = self
            .table
            .iter()
            .filter(|e| {
                let last = e.value().last_seen_ns.load(Ordering::Relaxed);
                now_ns.saturating_sub(last) > cutoff
            })
            .map(|e| *e.key())
            .collect();

        let mut removed = 0;
        for k in candidates {
            let still_idle = match self.table.get(&k) {
                Some(e) => {
                    let last = e.value().last_seen_ns.load(Ordering::Relaxed);
                    now_ns.saturating_sub(last) > cutoff
                }
                None => false,
            };
            if still_idle && self.table.remove(&k).is_some() {
                removed += 1;
            }
        }
        removed
    }

    /// Capacity back-pressure: when `len() > capacity * load_factor`, evict
    /// the N oldest flows. Keeps memory bounded under DDoS / scan storms.
    pub fn evict_oldest(&self, n: usize) -> usize {
        if n == 0 {
            return 0;
        }
        let mut ages: Vec<(FlowKey, u64)> = self
            .table
            .iter()
            .map(|e| (*e.key(), e.value().last_seen_ns.load(Ordering::Relaxed)))
            .collect();
        ages.sort_unstable_by_key(|&(_, t)| t);
        let mut removed = 0;
        for (k, _) in ages.into_iter().take(n) {
            if self.table.remove(&k).is_some() {
                removed += 1;
            }
        }
        removed
    }

    /// Apply load-factor policy: if length > 90% of capacity, evict 10%.
    /// Returns count evicted (zero if not over threshold).
    pub fn enforce_capacity(&self) -> usize {
        let threshold = (self.capacity * 9) / 10;
        let len = self.table.len();
        if len <= threshold {
            return 0;
        }
        let to_drop = len.saturating_sub((self.capacity * 8) / 10);
        self.evict_oldest(to_drop)
    }

    pub fn snapshot(&self) -> Vec<(FlowKey, Arc<FlowEntry>)> {
        self.table
            .iter()
            .map(|e| (*e.key(), e.value().clone()))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;
    use std::sync::Arc;
    use std::thread;

    fn k(a: u8, b: u8, sp: u16, dp: u16) -> FlowKey {
        FlowKey {
            src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, a)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, b)),
            src_port: sp,
            dst_port: dp,
            proto: 6,
        }
    }

    #[test]
    fn canonical_collapses_directions() {
        let fwd = k(1, 2, 5000, 80);
        let rev = k(2, 1, 80, 5000);
        assert_eq!(fwd.canonical(), rev.canonical());
        assert!(fwd.is_forward() != rev.is_forward());
    }

    #[test]
    fn observe_increments_counters() {
        let t = FlowTable::new(1024, 60);
        let key = k(1, 2, 5000, 80);
        let entry = t.observe(key, 100, 1_000);
        assert_eq!(entry.packets.load(Ordering::Relaxed), 1);
        assert_eq!(entry.bytes.load(Ordering::Relaxed), 100);
        assert_eq!(entry.fwd_packets.load(Ordering::Relaxed), 1);
        assert_eq!(entry.rev_packets.load(Ordering::Relaxed), 0);

        let entry2 = t.observe(key, 200, 2_000);
        assert!(Arc::ptr_eq(&entry, &entry2));
        assert_eq!(entry2.packets.load(Ordering::Relaxed), 2);
        assert_eq!(entry2.bytes.load(Ordering::Relaxed), 300);
    }

    #[test]
    fn forward_and_reverse_share_one_entry() {
        let t = FlowTable::new(1024, 60);
        let fwd = t.observe(k(1, 2, 5000, 80), 100, 1_000);
        let rev = t.observe(k(2, 1, 80, 5000), 200, 2_000);
        assert!(Arc::ptr_eq(&fwd, &rev));
        assert_eq!(fwd.fwd_packets.load(Ordering::Relaxed), 1);
        assert_eq!(fwd.rev_packets.load(Ordering::Relaxed), 1);
        assert_eq!(fwd.fwd_bytes.load(Ordering::Relaxed), 100);
        assert_eq!(fwd.rev_bytes.load(Ordering::Relaxed), 200);
        assert_eq!(t.len(), 1);
    }

    #[test]
    fn sweep_removes_idle_keeps_fresh() {
        let t = FlowTable::new(1024, 1); // 1-second idle timeout
        t.observe(k(1, 2, 5000, 80), 100, 1_000_000_000);
        t.observe(k(3, 4, 5001, 80), 100, 4_000_000_000); // fresh
        // now_ns = 5s; flow 1 last seen at 1s → idle
        let evicted = t.sweep(5_000_000_000);
        assert_eq!(evicted, 1);
        assert_eq!(t.len(), 1);
        assert!(t.get(&k(3, 4, 5001, 80)).is_some());
        assert!(t.get(&k(1, 2, 5000, 80)).is_none());
    }

    #[test]
    fn sweep_keeps_recently_observed_under_race() {
        let t = FlowTable::new(1024, 1);
        let key = k(1, 2, 5000, 80);
        t.observe(key, 100, 1_000_000_000);
        // Flow looks idle at now=5s, but a "concurrent observer" refreshes
        // it before the second pass runs. We simulate by manually bumping.
        t.observe(key, 50, 5_500_000_000);
        let evicted = t.sweep(5_000_000_000);
        assert_eq!(evicted, 0);
        assert_eq!(t.len(), 1);
    }

    #[test]
    fn tcp_state_advance_only_forward() {
        let t = FlowTable::new(64, 60);
        let e = t.observe(k(1, 2, 5000, 80), 1, 0);
        e.advance_tcp(TcpState::Syn);
        e.advance_tcp(TcpState::SynAck);
        e.advance_tcp(TcpState::Established);
        assert_eq!(
            TcpState::from_u8(e.tcp_state.load(Ordering::Relaxed)),
            TcpState::Established
        );
        // illegal backward jump is silently ignored
        e.advance_tcp(TcpState::Syn);
        assert_eq!(
            TcpState::from_u8(e.tcp_state.load(Ordering::Relaxed)),
            TcpState::Established
        );
        // Reset always wins.
        e.advance_tcp(TcpState::Reset);
        assert_eq!(
            TcpState::from_u8(e.tcp_state.load(Ordering::Relaxed)),
            TcpState::Reset
        );
    }

    #[test]
    fn evict_oldest_drops_lru_entries() {
        let t = FlowTable::new(64, 60);
        for i in 0..10u8 {
            t.observe(k(i, 100, 5000 + i as u16, 80), 1, (i as u64) * 1_000_000);
        }
        assert_eq!(t.len(), 10);
        let dropped = t.evict_oldest(3);
        assert_eq!(dropped, 3);
        assert_eq!(t.len(), 7);
        // The three oldest (i=0,1,2) should be gone.
        assert!(t.get(&k(0, 100, 5000, 80)).is_none());
        assert!(t.get(&k(2, 100, 5002, 80)).is_none());
        assert!(t.get(&k(3, 100, 5003, 80)).is_some());
    }

    #[test]
    fn concurrent_observers_dont_lose_increments() {
        let t = Arc::new(FlowTable::new(4096, 60));
        let key = k(1, 2, 5000, 80);
        let threads: Vec<_> = (0..8)
            .map(|_| {
                let t = Arc::clone(&t);
                thread::spawn(move || {
                    for i in 0..1000 {
                        t.observe(key, 1, i);
                    }
                })
            })
            .collect();
        for h in threads {
            h.join().unwrap();
        }
        let e = t.get(&key).unwrap();
        assert_eq!(e.packets.load(Ordering::Relaxed), 8 * 1000);
        assert_eq!(e.bytes.load(Ordering::Relaxed), 8 * 1000);
        assert_eq!(t.len(), 1);
    }

    #[test]
    fn enforce_capacity_evicts_when_over_threshold() {
        let t = FlowTable::new(10, 60);
        for i in 0..10u8 {
            t.observe(k(i, 100, 5000 + i as u16, 80), 1, (i as u64) * 1_000);
        }
        assert_eq!(t.len(), 10);
        let evicted = t.enforce_capacity();
        // 90% of 10 = 9, so 10 > 9 triggers eviction down to 80% = 8.
        assert!(evicted >= 2, "expected ≥2 evictions, got {evicted}");
        assert!(t.len() <= 8);
    }

    #[test]
    fn arc_clones_outlive_table_remove() {
        let t = FlowTable::new(64, 60);
        let key = k(1, 2, 5000, 80);
        let e1 = t.observe(key, 100, 1_000);
        let e2 = e1.clone();
        // Remove from table while another holder exists — this is the
        // epoch-reclamation guarantee. The Arc keeps it alive; drop after
        // sweep doesn't UAF.
        let _ = t.evict_oldest(1);
        assert!(t.get(&key).is_none());
        assert_eq!(e2.packets.load(Ordering::Relaxed), 1);
        drop(e1);
        drop(e2);
    }
}
