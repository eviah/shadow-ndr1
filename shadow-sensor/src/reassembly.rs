//! TCP stream reassembly and IPv4 defragmentation with bounded memory.
//!
//! Two separate primitives, both bounded so an adversary can't OOM the
//! sensor by withholding the final segment of a flow:
//!
//! 1. `TcpReassembler` — per-direction-of-flow object that consumes (seq,
//!    bytes) tuples in any order and emits the contiguous, deduplicated,
//!    in-order byte stream. Wrap-around sequence numbers are handled
//!    correctly via `seq_diff` (signed cast of wrapping subtraction).
//!
//! 2. `IpDefrag` — IPv4-style fragment reassembler keyed by
//!    `(src, dst, proto, ipid)`. Buffers chunks until either a final
//!    fragment + complete coverage assembles a whole datagram, or the
//!    per-key timeout expires.
//!
//! Both objects accept an explicit memory budget. Once the budget is
//! exceeded, *new* data is dropped rather than evicting in-flight state —
//! evicting in-flight reassembly would create false negatives that look
//! identical to a clean miss to higher layers, while drop-on-overflow at
//! least surfaces as `dropped_bytes` counter.

use std::collections::{BTreeMap, HashMap};
use std::net::IpAddr;

// =====================================================================
// TCP stream reassembly
// =====================================================================

/// Signed difference of TCP sequence numbers, taking wrap-around into
/// account. Result is in [-2^31, 2^31). Caller must trust that the true
/// distance is < 2^31 (TCP MAX_WINDOW guarantee).
#[inline]
pub fn seq_diff(a: u32, b: u32) -> i32 {
    a.wrapping_sub(b) as i32
}

#[derive(Debug)]
pub struct TcpReassembler {
    expected_seq: u32,
    delivered_bytes: u64,
    dropped_bytes: u64,
    pending: BTreeMap<u32, Vec<u8>>,
    pending_total: usize,
    max_pending: usize,
    initialized: bool,
}

impl TcpReassembler {
    pub fn new(max_pending_bytes: usize) -> Self {
        TcpReassembler {
            expected_seq: 0,
            delivered_bytes: 0,
            dropped_bytes: 0,
            pending: BTreeMap::new(),
            pending_total: 0,
            max_pending: max_pending_bytes,
            initialized: false,
        }
    }

    /// Pin the next-expected sequence number. Typically called when the
    /// first SYN (or first observed segment) is seen.
    pub fn set_isn(&mut self, isn: u32) {
        self.expected_seq = isn;
        self.initialized = true;
    }

    pub fn delivered(&self) -> u64 { self.delivered_bytes }
    pub fn dropped(&self) -> u64 { self.dropped_bytes }
    pub fn pending_bytes(&self) -> usize { self.pending_total }
    pub fn expected_seq(&self) -> u32 { self.expected_seq }

    /// Feed one TCP segment. Returns the newly-contiguous bytes appended
    /// to the in-order stream by this call (may be empty if the segment
    /// was buffered, retransmitted, or dropped).
    pub fn ingest(&mut self, seq: u32, data: &[u8]) -> Vec<u8> {
        if !self.initialized {
            // Auto-anchor on first segment if caller forgot.
            self.set_isn(seq);
        }
        let mut output = Vec::new();
        if data.is_empty() {
            return output;
        }

        let (cur_seq, cur_data) = match self.trim_against_expected(seq, data) {
            TrimResult::AllRetransmit => return output,
            TrimResult::Future => {
                self.buffer(seq, data.to_vec());
                return output;
            }
            TrimResult::Active(s, d) => (s, d),
        };

        // In-order append.
        output.extend_from_slice(&cur_data);
        self.expected_seq = self.expected_seq.wrapping_add(cur_data.len() as u32);
        self.delivered_bytes += cur_data.len() as u64;
        let _ = cur_seq;

        // Drain whatever pending segments are now contiguous or overlap
        // with the freshly-advanced expected_seq.
        loop {
            let Some((&pseq, _)) = self.pending.iter().next() else { break };
            let diff = seq_diff(pseq, self.expected_seq);
            if diff > 0 {
                break;
            }
            let pdata = self.pending.remove(&pseq).unwrap();
            self.pending_total -= pdata.len();
            if diff < 0 {
                let skip = (-diff) as usize;
                if skip >= pdata.len() {
                    // Entirely covered already.
                    continue;
                }
                output.extend_from_slice(&pdata[skip..]);
                self.expected_seq = self.expected_seq.wrapping_add((pdata.len() - skip) as u32);
                self.delivered_bytes += (pdata.len() - skip) as u64;
            } else {
                output.extend_from_slice(&pdata);
                self.expected_seq = self.expected_seq.wrapping_add(pdata.len() as u32);
                self.delivered_bytes += pdata.len() as u64;
            }
        }

        output
    }

    fn trim_against_expected(&self, seq: u32, data: &[u8]) -> TrimResult {
        let diff = seq_diff(seq, self.expected_seq);
        if diff < 0 {
            let skip = (-diff) as i64;
            if skip as usize >= data.len() {
                return TrimResult::AllRetransmit;
            }
            return TrimResult::Active(self.expected_seq, data[skip as usize..].to_vec());
        }
        if diff == 0 {
            return TrimResult::Active(seq, data.to_vec());
        }
        TrimResult::Future
    }

    fn buffer(&mut self, seq: u32, data: Vec<u8>) {
        if self.pending_total + data.len() > self.max_pending {
            self.dropped_bytes += data.len() as u64;
            return;
        }
        // If a same-seq entry exists, keep the longer one (likely the
        // newer / more complete copy).
        match self.pending.get(&seq) {
            Some(existing) if existing.len() >= data.len() => {
                self.dropped_bytes += data.len() as u64;
            }
            _ => {
                if let Some(prev) = self.pending.insert(seq, data.clone()) {
                    self.pending_total -= prev.len();
                }
                self.pending_total += data.len();
            }
        }
    }
}

enum TrimResult {
    AllRetransmit,
    Future,
    Active(u32, Vec<u8>),
}

// =====================================================================
// IPv4 defragmentation
// =====================================================================

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct DefragKey {
    pub src: IpAddr,
    pub dst: IpAddr,
    pub proto: u8,
    pub ipid: u32,
}

#[derive(Debug)]
struct FragmentState {
    chunks: BTreeMap<u32, Vec<u8>>,
    total_length: Option<u32>,
    last_ns: u64,
    bytes: usize,
}

#[derive(Debug)]
pub struct IpDefrag {
    frags: HashMap<DefragKey, FragmentState>,
    total: usize,
    max_total: usize,
    timeout_ns: u64,
    dropped: u64,
    completed: u64,
    timed_out: u64,
}

impl IpDefrag {
    pub fn new(max_total_bytes: usize, timeout_secs: u64) -> Self {
        IpDefrag {
            frags: HashMap::new(),
            total: 0,
            max_total: max_total_bytes,
            timeout_ns: timeout_secs.saturating_mul(1_000_000_000),
            dropped: 0,
            completed: 0,
            timed_out: 0,
        }
    }

    pub fn buffered_bytes(&self) -> usize { self.total }
    pub fn in_flight(&self) -> usize { self.frags.len() }
    pub fn dropped(&self) -> u64 { self.dropped }
    pub fn completed(&self) -> u64 { self.completed }
    pub fn timed_out(&self) -> u64 { self.timed_out }

    /// Feed one IP fragment. Returns `Some(bytes)` if this completes a
    /// datagram, `None` otherwise.
    pub fn ingest(
        &mut self,
        key: DefragKey,
        offset: u32,
        more_fragments: bool,
        data: Vec<u8>,
        now_ns: u64,
    ) -> Option<Vec<u8>> {
        if data.is_empty() {
            return None;
        }
        if self.total + data.len() > self.max_total {
            self.dropped += data.len() as u64;
            return None;
        }

        let st = self
            .frags
            .entry(key)
            .or_insert_with(|| FragmentState {
                chunks: BTreeMap::new(),
                total_length: None,
                last_ns: now_ns,
                bytes: 0,
            });
        st.last_ns = now_ns;

        let added = data.len();
        match st.chunks.insert(offset, data) {
            Some(prev) => {
                self.total -= prev.len();
                st.bytes -= prev.len();
            }
            None => {}
        }
        st.bytes += added;
        self.total += added;

        if !more_fragments {
            // Final fragment fixes the datagram length.
            let chunk_len = st.chunks.get(&offset).map(|v| v.len() as u32).unwrap_or(0);
            st.total_length = Some(offset + chunk_len);
        }

        if let Some(total_len) = st.total_length {
            if Self::has_complete_coverage(&st.chunks, total_len) {
                let st = self.frags.remove(&key).unwrap();
                self.total -= st.bytes;
                self.completed += 1;
                let mut out = Vec::with_capacity(total_len as usize);
                for (off, bytes) in &st.chunks {
                    let off = *off as usize;
                    if off > out.len() {
                        return None; // gap — should not happen if has_complete_coverage was true
                    }
                    if off < out.len() {
                        // Overlapping fragment — keep what we have, append tail.
                        let overlap = out.len() - off;
                        if overlap < bytes.len() {
                            out.extend_from_slice(&bytes[overlap..]);
                        }
                    } else {
                        out.extend_from_slice(bytes);
                    }
                }
                return Some(out);
            }
        }
        None
    }

    fn has_complete_coverage(chunks: &BTreeMap<u32, Vec<u8>>, total_len: u32) -> bool {
        let mut cursor: u32 = 0;
        for (&off, bytes) in chunks {
            if off > cursor {
                return false; // gap
            }
            let end = off + bytes.len() as u32;
            if end > cursor {
                cursor = end;
            }
        }
        cursor >= total_len
    }

    /// Evict in-flight fragments that haven't been touched within the
    /// timeout window. Returns count timed out.
    pub fn sweep(&mut self, now_ns: u64) -> usize {
        let cutoff = self.timeout_ns;
        let mut to_drop: Vec<DefragKey> = Vec::new();
        for (k, st) in &self.frags {
            if now_ns.saturating_sub(st.last_ns) > cutoff {
                to_drop.push(*k);
            }
        }
        let n = to_drop.len();
        for k in to_drop {
            if let Some(st) = self.frags.remove(&k) {
                self.total -= st.bytes;
                self.timed_out += 1;
            }
        }
        n
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    // ---------- TCP reassembly ----------

    #[test]
    fn tcp_in_order_segments_pass_through() {
        let mut r = TcpReassembler::new(4096);
        r.set_isn(1000);
        let out = r.ingest(1000, b"hello ");
        assert_eq!(out, b"hello ");
        let out = r.ingest(1006, b"world");
        assert_eq!(out, b"world");
        assert_eq!(r.delivered(), 11);
        assert_eq!(r.pending_bytes(), 0);
    }

    #[test]
    fn tcp_out_of_order_buffers_then_drains() {
        let mut r = TcpReassembler::new(4096);
        r.set_isn(1000);
        let out = r.ingest(1006, b"world"); // future
        assert!(out.is_empty());
        assert_eq!(r.pending_bytes(), 5);

        let out = r.ingest(1000, b"hello "); // fills the gap
        assert_eq!(out, b"hello world");
        assert_eq!(r.pending_bytes(), 0);
        assert_eq!(r.delivered(), 11);
    }

    #[test]
    fn tcp_pure_retransmit_is_dropped() {
        let mut r = TcpReassembler::new(4096);
        r.set_isn(1000);
        r.ingest(1000, b"hello");
        let out = r.ingest(1000, b"hello"); // exact retransmit
        assert!(out.is_empty());
        assert_eq!(r.delivered(), 5);
    }

    #[test]
    fn tcp_overlapping_segment_yields_only_new_tail() {
        let mut r = TcpReassembler::new(4096);
        r.set_isn(1000);
        r.ingest(1000, b"hello"); // 1000..1005
        let out = r.ingest(1003, b"loWORLD"); // 3 overlap, then 4 new
        assert_eq!(out, b"WORLD".to_vec());
        assert_eq!(r.delivered(), 10);
    }

    #[test]
    fn tcp_three_segments_arriving_reverse_order() {
        let mut r = TcpReassembler::new(4096);
        r.set_isn(0);
        assert!(r.ingest(10, b"CCCCC").is_empty());
        assert!(r.ingest(5, b"BBBBB").is_empty());
        let out = r.ingest(0, b"AAAAA");
        assert_eq!(out, b"AAAAABBBBBCCCCC");
        assert_eq!(r.pending_bytes(), 0);
    }

    #[test]
    fn tcp_handles_seq_wraparound() {
        let mut r = TcpReassembler::new(4096);
        // isn = u32::MAX - 2; 5 bytes span [isn..isn+5) which wraps past 0.
        let isn = u32::MAX - 2;
        r.set_isn(isn);
        let out = r.ingest(isn, b"abcde");
        assert_eq!(out, b"abcde");
        // Next expected = isn + 5 mod 2^32 = 2.
        assert_eq!(r.expected_seq(), 2);
        let out = r.ingest(2, b"fgh");
        assert_eq!(out, b"fgh");
        assert_eq!(r.expected_seq(), 5);
    }

    #[test]
    fn tcp_pending_budget_drops_overflow() {
        let mut r = TcpReassembler::new(8);
        r.set_isn(0);
        // expected = 0; future segs at 100, 200 each 6 bytes → first fits, second drops.
        assert!(r.ingest(100, b"ABCDEF").is_empty());
        assert_eq!(r.pending_bytes(), 6);
        assert!(r.ingest(200, b"GHIJKL").is_empty());
        assert_eq!(r.pending_bytes(), 6);
        assert_eq!(r.dropped(), 6);
    }

    // ---------- IP defrag ----------

    fn dkey() -> DefragKey {
        DefragKey {
            src: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            dst: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            proto: 17,
            ipid: 0xBEEF,
        }
    }

    #[test]
    fn defrag_two_in_order_fragments() {
        let mut d = IpDefrag::new(4096, 30);
        let r = d.ingest(dkey(), 0, true, b"hello ".to_vec(), 0);
        assert!(r.is_none());
        let r = d.ingest(dkey(), 6, false, b"world".to_vec(), 1);
        assert_eq!(r, Some(b"hello world".to_vec()));
        assert_eq!(d.in_flight(), 0);
        assert_eq!(d.completed(), 1);
    }

    #[test]
    fn defrag_two_out_of_order_fragments() {
        let mut d = IpDefrag::new(4096, 30);
        let r = d.ingest(dkey(), 6, false, b"world".to_vec(), 0);
        assert!(r.is_none()); // total_length known, but missing 0..6
        let r = d.ingest(dkey(), 0, true, b"hello ".to_vec(), 1);
        assert_eq!(r, Some(b"hello world".to_vec()));
    }

    #[test]
    fn defrag_three_fragments_random_order() {
        let mut d = IpDefrag::new(4096, 30);
        assert!(d.ingest(dkey(), 4, true, b"BBBB".to_vec(), 0).is_none());
        assert!(d.ingest(dkey(), 8, false, b"CCC".to_vec(), 1).is_none());
        let r = d.ingest(dkey(), 0, true, b"AAAA".to_vec(), 2);
        assert_eq!(r, Some(b"AAAABBBBCCC".to_vec()));
    }

    #[test]
    fn defrag_memory_bound_drops_overflow() {
        let mut d = IpDefrag::new(8, 30);
        let r = d.ingest(dkey(), 0, true, b"ABCDEFGH".to_vec(), 0);
        assert!(r.is_none());
        let r = d.ingest(dkey(), 8, false, b"IJKL".to_vec(), 1);
        assert!(r.is_none()); // dropped — over budget
        assert_eq!(d.dropped(), 4);
    }

    #[test]
    fn defrag_timeout_evicts_incomplete() {
        let mut d = IpDefrag::new(4096, 1);
        d.ingest(dkey(), 0, true, b"ABCD".to_vec(), 1_000_000_000);
        // No closing fragment; sweep at t=5s.
        let evicted = d.sweep(5_000_000_000);
        assert_eq!(evicted, 1);
        assert_eq!(d.in_flight(), 0);
        assert_eq!(d.timed_out(), 1);
        assert_eq!(d.buffered_bytes(), 0);
    }

    #[test]
    fn defrag_does_not_evict_fresh_entries() {
        let mut d = IpDefrag::new(4096, 1);
        d.ingest(dkey(), 0, true, b"ABCD".to_vec(), 4_500_000_000);
        let evicted = d.sweep(5_000_000_000); // only 0.5s old
        assert_eq!(evicted, 0);
        assert_eq!(d.in_flight(), 1);
    }
}
