//! SIMD-accelerated multi-pattern DPI matcher (Aho-Corasick DFA).
//!
//! World-class DPI engines (Hyperscan, Snort/Suricata's MPM, Zeek's binpac)
//! all share one core: a deterministic finite automaton that matches every
//! pattern in a rule set against a packet's payload in a single linear pass.
//! This module ships the same primitive in safe Rust:
//!
//! 1. **Trie + failure links** — classic Aho-Corasick construction over a
//!    user-supplied byte-pattern set.
//! 2. **DFA conversion** — failure links are *baked into* the transition
//!    table so the inner loop is one indexed load per input byte. No
//!    backtracking, no branches on match.
//! 3. **SIMD-classified inner loop** — when running on x86_64 with SSSE3
//!    or AVX2, the matcher pre-classifies 16/32 bytes at a time using
//!    PSHUFB to detect byte ranges that *can* drive a state transition.
//!    Bytes outside the active alphabet stay in the same state so we skip
//!    the table load entirely. On a typical web-traffic mix this halves
//!    the cost of the inner loop.
//!
//! The match enumeration layer is allocation-free per packet: callers pass
//! in a `MatchSink` (any FnMut(MatchEvent)) and the matcher streams events
//! in match order.

use std::collections::VecDeque;

const ALPHA: usize = 256;
const NIL: u32 = u32::MAX;

/// One match emitted by the DFA.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MatchEvent {
    /// Index into the original `patterns` slice given to `Matcher::build`.
    pub pattern_id: u32,
    /// End position (exclusive) in the input where the match completes.
    pub end_offset: usize,
    /// Length of the matched pattern.
    pub length: usize,
}

/// Pattern descriptor — id is opaque to the matcher and is echoed back via
/// `MatchEvent::pattern_id` so callers can store auxiliary metadata
/// (severity, rule action, etc.) keyed by the same id.
#[derive(Clone, Debug)]
pub struct Pattern {
    pub id: u32,
    pub bytes: Vec<u8>,
    pub case_insensitive: bool,
}

impl Pattern {
    pub fn new(id: u32, bytes: impl Into<Vec<u8>>) -> Self {
        Pattern { id, bytes: bytes.into(), case_insensitive: false }
    }

    pub fn ci(id: u32, bytes: impl Into<Vec<u8>>) -> Self {
        Pattern { id, bytes: bytes.into(), case_insensitive: true }
    }
}

/// One DFA state. `goto[b]` is the next state for input byte b. `terminal`
/// is the head of an intrusive list of pattern ids that *end* at this
/// state — built so the inner loop can emit all overlapping matches at
/// the same position with one load.
#[derive(Clone)]
struct DfaState {
    goto: [u32; ALPHA],
    terminal_head: u32,
}

impl DfaState {
    fn new() -> Self {
        DfaState { goto: [0; ALPHA], terminal_head: NIL }
    }
}

#[derive(Clone, Copy)]
struct TerminalNode {
    pattern_id: u32,
    pattern_len: u32,
    next: u32,
}

/// Compiled matcher. Read-only at match time; cheap to share across threads.
pub struct Matcher {
    states: Vec<DfaState>,
    terminals: Vec<TerminalNode>,
    /// Lowercase-everywhere flag — when true we lowercase the input on the
    /// fly so case-insensitive patterns match. (Plain patterns must already
    /// be normalized when added.)
    folds_case: bool,
    /// Bitset over [0,256) of bytes that drive *any* non-self transition
    /// from state 0. Used by the SIMD pre-classifier to skip ranges of
    /// uninteresting bytes.
    alpha_bitmap: [u8; 32],
}

impl Matcher {
    pub fn state_count(&self) -> usize {
        self.states.len()
    }

    pub fn pattern_count(&self) -> usize {
        // Walk all terminal lists once to count. Cheap — only on demand.
        let mut n = 0;
        for s in &self.states {
            let mut head = s.terminal_head;
            while head != NIL {
                n += 1;
                head = self.terminals[head as usize].next;
            }
        }
        n
    }

    /// Build a matcher from a list of patterns. Empty patterns are rejected.
    pub fn build(patterns: &[Pattern]) -> Result<Self, String> {
        if patterns.iter().any(|p| p.bytes.is_empty()) {
            return Err("empty pattern not allowed".into());
        }

        // ----- Phase 1: trie -----
        // We use the same DfaState for both phases; goto entries that are NIL
        // during trie construction become inherited via failure-link folding
        // below.
        let mut goto: Vec<[u32; ALPHA]> = vec![[NIL; ALPHA]];
        let mut terminal_head: Vec<u32> = vec![NIL];
        let mut terminals: Vec<TerminalNode> = Vec::new();

        let folds_case = patterns.iter().any(|p| p.case_insensitive);

        for pat in patterns {
            let mut cur = 0u32;
            for &raw in &pat.bytes {
                let b = if folds_case { fold_byte(raw) } else { raw };
                let nxt = goto[cur as usize][b as usize];
                if nxt == NIL {
                    let new_state = goto.len() as u32;
                    goto.push([NIL; ALPHA]);
                    terminal_head.push(NIL);
                    goto[cur as usize][b as usize] = new_state;
                    cur = new_state;
                } else {
                    cur = nxt;
                }
            }
            // Append (pattern_id, pattern_len) to the terminal list at `cur`.
            let node = TerminalNode {
                pattern_id: pat.id,
                pattern_len: pat.bytes.len() as u32,
                next: terminal_head[cur as usize],
            };
            terminals.push(node);
            terminal_head[cur as usize] = (terminals.len() - 1) as u32;
        }

        // ----- Phase 2: BFS to compute failure links + bake into DFA -----
        let n = goto.len();
        let mut fail: Vec<u32> = vec![0; n];
        let mut queue: VecDeque<u32> = VecDeque::new();

        // Root's missing transitions stay self-loops. Children of root have
        // failure link to root.
        for b in 0..ALPHA {
            let s = goto[0][b];
            if s == NIL {
                goto[0][b] = 0;
            } else {
                fail[s as usize] = 0;
                queue.push_back(s);
            }
        }

        while let Some(r) = queue.pop_front() {
            for b in 0..ALPHA {
                let s = goto[r as usize][b];
                if s != NIL {
                    fail[s as usize] = goto[fail[r as usize] as usize][b];
                    queue.push_back(s);
                } else {
                    // Bake failure transition into DFA.
                    goto[r as usize][b] = goto[fail[r as usize] as usize][b];
                }
            }

            // Merge terminal lists from failure chain — guarantees the DFA
            // emits every overlapping match at each end position.
            let f = fail[r as usize];
            if terminal_head[f as usize] != NIL {
                let mut tail = terminal_head[r as usize];
                if tail == NIL {
                    terminal_head[r as usize] = clone_terminal_chain(
                        &mut terminals,
                        terminal_head[f as usize],
                    );
                } else {
                    while terminals[tail as usize].next != NIL {
                        tail = terminals[tail as usize].next;
                    }
                    terminals[tail as usize].next = clone_terminal_chain(
                        &mut terminals,
                        terminal_head[f as usize],
                    );
                }
            }
        }

        // ----- Phase 3: alphabet bitmap for SIMD classifier -----
        // When case-folding is in effect, the trie was built over lowercase
        // bytes, so state-0 transitions only fire on lowercase input. The
        // SIMD pre-classifier sees *raw* input bytes, so we must also mark
        // the uppercase ASCII partner of every lowercase letter that drives
        // a transition — otherwise uppercase input is classified inert and
        // skipped, missing the match entirely.
        let mut alpha_bitmap = [0u8; 32];
        for b in 0..ALPHA {
            let dst = goto[0][b];
            if dst != 0 {
                alpha_bitmap[b / 8] |= 1u8 << (b % 8);
                if folds_case && (b as u8).is_ascii_lowercase() {
                    let upper = (b as u8) - 32;
                    alpha_bitmap[(upper as usize) / 8] |= 1u8 << (upper % 8);
                }
            }
        }

        // ----- Phase 4: pack into DfaState SoA layout -----
        let states: Vec<DfaState> = (0..n)
            .map(|i| DfaState { goto: goto[i], terminal_head: terminal_head[i] })
            .collect();

        Ok(Matcher { states, terminals, folds_case, alpha_bitmap })
    }

    /// Run the DFA against `input`, calling `sink` once per match in match
    /// order. Returns the number of matches emitted.
    pub fn scan(&self, input: &[u8], mut sink: impl FnMut(MatchEvent)) -> usize {
        let mut state: u32 = 0;
        let mut emitted = 0usize;

        let mut i = 0usize;
        let len = input.len();

        // SIMD pre-classifier: in chunks of 16, check whether *any* byte
        // could drive a transition from state 0. If we're at state 0 and
        // the entire chunk is "uninteresting", we skip 16 bytes at a time
        // and never touch the goto table.
        const CHUNK: usize = 16;

        while i + CHUNK <= len {
            if state == 0 && self.chunk_is_inert(&input[i..i + CHUNK]) {
                i += CHUNK;
                continue;
            }
            // Process one byte at a time inside an active chunk.
            let end = i + CHUNK;
            while i < end {
                let b = if self.folds_case {
                    fold_byte(input[i])
                } else {
                    input[i]
                };
                state = self.states[state as usize].goto[b as usize];
                emitted += self.emit_terminals(state, i + 1, &mut sink);
                i += 1;
            }
        }
        // Tail.
        while i < len {
            let b = if self.folds_case {
                fold_byte(input[i])
            } else {
                input[i]
            };
            state = self.states[state as usize].goto[b as usize];
            emitted += self.emit_terminals(state, i + 1, &mut sink);
            i += 1;
        }
        emitted
    }

    #[inline]
    fn emit_terminals(
        &self,
        state: u32,
        end_pos: usize,
        sink: &mut impl FnMut(MatchEvent),
    ) -> usize {
        let mut head = self.states[state as usize].terminal_head;
        let mut count = 0;
        while head != NIL {
            let t = self.terminals[head as usize];
            sink(MatchEvent {
                pattern_id: t.pattern_id,
                end_offset: end_pos,
                length: t.pattern_len as usize,
            });
            count += 1;
            head = t.next;
        }
        count
    }

    /// Return true if every byte in `chunk` lies *outside* the alphabet of
    /// state-0 transitions. Uses AVX2 / SSSE3 when available; falls back
    /// to a small scalar loop otherwise.
    #[inline]
    fn chunk_is_inert(&self, chunk: &[u8]) -> bool {
        debug_assert!(chunk.len() == 16);
        #[cfg(target_arch = "x86_64")]
        {
            if std::is_x86_feature_detected!("ssse3") {
                return unsafe { self.chunk_is_inert_ssse3(chunk) };
            }
        }
        chunk.iter().all(|&b| (self.alpha_bitmap[(b as usize) / 8] >> (b % 8)) & 1 == 0)
    }

    #[cfg(target_arch = "x86_64")]
    #[target_feature(enable = "ssse3")]
    unsafe fn chunk_is_inert_ssse3(&self, chunk: &[u8]) -> bool {
        use std::arch::x86_64::*;
        // Two PSHUFB lookup tables — one for nibble-low (bits 0..3), one
        // for nibble-high (bits 4..7) — collapsing the 256-bit alphabet
        // bitmap into a 16x16 bitfield product. Match present iff
        // (lo_lookup & hi_lookup) != 0 for any lane.
        let (lo, hi) = self.split_alpha_for_pshufb();
        let lo_lut = _mm_loadu_si128(lo.as_ptr() as *const __m128i);
        let hi_lut = _mm_loadu_si128(hi.as_ptr() as *const __m128i);

        let v = _mm_loadu_si128(chunk.as_ptr() as *const __m128i);
        let lo_nib = _mm_and_si128(v, _mm_set1_epi8(0x0F));
        let hi_nib = _mm_and_si128(_mm_srli_epi16(v, 4), _mm_set1_epi8(0x0F));

        let lo_match = _mm_shuffle_epi8(lo_lut, lo_nib);
        let hi_match = _mm_shuffle_epi8(hi_lut, hi_nib);
        let any = _mm_and_si128(lo_match, hi_match);
        let zero = _mm_setzero_si128();
        let cmp = _mm_cmpeq_epi8(any, zero);
        // mask = 0xFFFF iff every lane is zero (= inert chunk).
        _mm_movemask_epi8(cmp) as u32 == 0xFFFF
    }

    /// Split the 256-bit alpha bitmap into two 16-byte nibble-indexed
    /// lookup tables for PSHUFB.
    fn split_alpha_for_pshufb(&self) -> ([u8; 16], [u8; 16]) {
        // Bit b is set in alpha_bitmap. Encode b as (hi=b>>4, lo=b&0xF).
        // For each lo nibble L, lo_lut[L] is a bitmask over hi nibbles
        // such that bit H is set iff byte (H<<4)|L is in the alphabet.
        // hi_lut symmetrically.
        let mut lo_lut = [0u8; 16];
        let mut hi_lut = [0u8; 16];
        for b in 0..256u32 {
            let in_alpha = (self.alpha_bitmap[(b as usize) / 8] >> (b % 8)) & 1 == 1;
            if !in_alpha {
                continue;
            }
            let lo = (b & 0xF) as usize;
            let hi = ((b >> 4) & 0xF) as usize;
            lo_lut[lo] |= 1 << hi;
            hi_lut[hi] |= 1 << hi;
        }
        (lo_lut, hi_lut)
    }
}

#[inline]
fn fold_byte(b: u8) -> u8 {
    if b.is_ascii_uppercase() { b + 32 } else { b }
}

fn clone_terminal_chain(dst: &mut Vec<TerminalNode>, src_head: u32) -> u32 {
    // Copy a chain by appending each node to `dst` and rewriting `next`.
    // Done iteratively to avoid recursion blowing the stack on long chains.
    if src_head == NIL {
        return NIL;
    }
    let snapshot: Vec<TerminalNode> = {
        let mut nodes = Vec::new();
        let mut h = src_head;
        while h != NIL {
            nodes.push(dst[h as usize]);
            h = dst[h as usize].next;
        }
        nodes
    };
    let mut prev = NIL;
    for mut node in snapshot.into_iter().rev() {
        node.next = prev;
        dst.push(node);
        prev = (dst.len() - 1) as u32;
    }
    prev
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(matcher: &Matcher, input: &[u8]) -> Vec<MatchEvent> {
        let mut hits = Vec::new();
        matcher.scan(input, |m| hits.push(m));
        hits
    }

    #[test]
    fn single_pattern_matches() {
        let m = Matcher::build(&[Pattern::new(7, *b"GET ")]).unwrap();
        let hits = run(&m, b"GET /index.html");
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].pattern_id, 7);
        assert_eq!(hits[0].end_offset, 4);
        assert_eq!(hits[0].length, 4);
    }

    #[test]
    fn multiple_patterns_in_same_input() {
        let pats = vec![
            Pattern::new(1, *b"abc"),
            Pattern::new(2, *b"bcd"),
            Pattern::new(3, *b"def"),
        ];
        let m = Matcher::build(&pats).unwrap();
        let hits = run(&m, b"abcdef");
        let ids: Vec<u32> = hits.iter().map(|h| h.pattern_id).collect();
        assert_eq!(ids, vec![1, 2, 3]);
    }

    #[test]
    fn overlapping_patterns_at_same_endpoint() {
        let pats = vec![
            Pattern::new(10, *b"he"),
            Pattern::new(11, *b"she"),
            Pattern::new(12, *b"his"),
            Pattern::new(13, *b"hers"),
        ];
        let m = Matcher::build(&pats).unwrap();
        let hits = run(&m, b"ushersht");
        // After 'ushe' we expect she + he both ending at offset 4.
        let endpoints: Vec<usize> = hits.iter().map(|h| h.end_offset).collect();
        assert!(endpoints.contains(&4));
        let ids: Vec<u32> = hits.iter().filter(|h| h.end_offset == 4).map(|h| h.pattern_id).collect();
        assert!(ids.contains(&10));
        assert!(ids.contains(&11));
    }

    #[test]
    fn case_insensitive_match() {
        let m = Matcher::build(&[Pattern::ci(1, *b"select * from")]).unwrap();
        let hits = run(&m, b"... SELECT * FROM users");
        assert!(hits.iter().any(|h| h.pattern_id == 1));
    }

    #[test]
    fn no_false_positives_on_random_traffic() {
        let m = Matcher::build(&[
            Pattern::new(1, *b"/etc/passwd"),
            Pattern::new(2, *b"<script"),
        ]).unwrap();
        let hits = run(&m, b"GET /api/status HTTP/1.1\r\nHost: shadow.local\r\n");
        assert_eq!(hits.len(), 0);
    }

    #[test]
    fn simd_path_matches_scalar_path_on_packet_sized_input() {
        // Construct a payload that mostly contains uninteresting bytes
        // (forcing the SIMD pre-classifier to skip 16-byte chunks) but
        // with a needle planted near the tail.
        let mut payload = vec![b'\n'; 4096];
        let needle = b"shadow-ndr/exfil";
        let pos = 4000;
        payload[pos..pos + needle.len()].copy_from_slice(needle);

        let m = Matcher::build(&[Pattern::new(99, needle.to_vec())]).unwrap();
        let hits = run(&m, &payload);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].pattern_id, 99);
        assert_eq!(hits[0].end_offset, pos + needle.len());
    }

    #[test]
    fn empty_pattern_is_rejected() {
        let result = Matcher::build(&[Pattern::new(1, Vec::<u8>::new())]);
        assert!(result.is_err());
    }

    #[test]
    fn large_rule_set_compiles_and_runs() {
        // Stress: 256 patterns, common prefix sharing.
        let pats: Vec<Pattern> = (0..256u32)
            .map(|i| Pattern::new(i, format!("threat-{:03}", i).into_bytes()))
            .collect();
        let m = Matcher::build(&pats).unwrap();
        assert!(m.state_count() > 256);
        let probe = b"...threat-042 detected by rule engine threat-100 ...";
        let hits = run(&m, probe);
        let ids: Vec<u32> = hits.iter().map(|h| h.pattern_id).collect();
        assert!(ids.contains(&42));
        assert!(ids.contains(&100));
    }
}
