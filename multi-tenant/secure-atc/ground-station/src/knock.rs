//! Knock decoder, replay window, and per-aircraft strike state.
//!
//! Spec §3 (Phase 1 KNOCK) and §7.4 (Replay window). The replay window
//! is a 256-bit bitmap shifted by `seq` deltas; it lives in static memory
//! per session, never reallocated.

use std::collections::HashMap;

use crate::crypto::{knock_eq, knock_token};
use crate::protocol::{
    KNOCK_TOKEN_LEN, KNOCK_WINDOW_S, LOCKOUT_AFTER_STRIKES, LOCKOUT_HOLD_S, LOCKOUT_WINDOW_S,
    REPLAY_WINDOW,
};

/// Outcome of a knock-token verification.
#[derive(Debug, PartialEq, Eq)]
pub enum KnockVerdict {
    /// Token matched the current or previous bucket and the aircraft is
    /// not currently locked out — handshake may proceed.
    Accept,
    /// Token did not match. Drop silently; strike count was incremented.
    Drop,
    /// Aircraft is in lockout; drop silently and do not increment.
    LockedOut,
}

/// Per-aircraft strike state. Held in HSM in production; this in-memory
/// shape mirrors the logic.
#[derive(Default, Debug, Clone)]
struct StrikeRecord {
    /// Wall-clock seconds of recent strikes; only entries within
    /// [`LOCKOUT_WINDOW_S`] are counted.
    timestamps: Vec<u64>,
    /// Lockout expiry, if any.
    locked_until: Option<u64>,
}

impl StrikeRecord {
    fn add_strike(&mut self, now_s: u64) {
        let cutoff = now_s.saturating_sub(LOCKOUT_WINDOW_S);
        self.timestamps.retain(|t| *t >= cutoff);
        self.timestamps.push(now_s);

        if u32::try_from(self.timestamps.len()).unwrap_or(u32::MAX) >= LOCKOUT_AFTER_STRIKES {
            self.locked_until = Some(now_s + LOCKOUT_HOLD_S);
            self.timestamps.clear();
        }
    }

    fn is_locked_out(&mut self, now_s: u64) -> bool {
        match self.locked_until {
            Some(t) if now_s < t => true,
            Some(_) => {
                self.locked_until = None;
                false
            }
            None => false,
        }
    }

    fn reset(&mut self) {
        self.timestamps.clear();
    }
}

/// Knock decoder + per-aircraft strike state.
///
/// In production, `k_master` lookup happens inside the HSM via the
/// [`crate::hsm`] interface; here we accept the closure-style lookup
/// to keep the module testable in isolation.
pub struct KnockDecoder {
    id_g: u32,
    strikes: HashMap<u64, StrikeRecord>,
}

impl KnockDecoder {
    /// Construct for a given ground-station id.
    #[must_use]
    pub fn new(id_g: u32) -> Self {
        Self {
            id_g,
            strikes: HashMap::new(),
        }
    }

    /// Verify a knock token.
    ///
    /// `k_master_lookup` MUST return `None` if `id_a` is not in the
    /// current enrolment set — that case is treated as `Drop`, not as
    /// a locked-out path, because we never tell the attacker whether
    /// `id_a` is enrolled.
    pub fn verify<F>(
        &mut self,
        id_a: u64,
        nonce_a: &[u8; 16],
        token: &[u8; KNOCK_TOKEN_LEN],
        now_s: u64,
        k_master_lookup: F,
    ) -> KnockVerdict
    where
        F: FnOnce(u64) -> Option<[u8; 32]>,
    {
        let _ = nonce_a; // nonce reuse policing is in the session layer

        let entry = self.strikes.entry(id_a).or_default();
        if entry.is_locked_out(now_s) {
            return KnockVerdict::LockedOut;
        }

        let Some(k_master) = k_master_lookup(id_a) else {
            // Indistinguishable from a token mismatch on the operational
            // plane; we DO NOT increment strikes for non-enrolled ids
            // (would otherwise allow an attacker to lock out an arbitrary
            // id by guessing it).
            return KnockVerdict::Drop;
        };

        let bucket = now_s / KNOCK_WINDOW_S;
        let cur = knock_token(&k_master, id_a, self.id_g, bucket);
        let prev = knock_token(&k_master, id_a, self.id_g, bucket.saturating_sub(1));

        if knock_eq(&cur, token) || knock_eq(&prev, token) {
            entry.reset();
            KnockVerdict::Accept
        } else {
            entry.add_strike(now_s);
            KnockVerdict::Drop
        }
    }

    /// Force a strike — used by §7.3 step 5 (AEAD failure in session).
    pub fn record_strike(&mut self, id_a: u64, now_s: u64) {
        let entry = self.strikes.entry(id_a).or_default();
        entry.add_strike(now_s);
    }

    /// Query whether an aircraft is locked out.
    #[must_use]
    pub fn is_locked_out(&mut self, id_a: u64, now_s: u64) -> bool {
        self.strikes
            .entry(id_a)
            .or_default()
            .is_locked_out(now_s)
    }
}

/// Replay window per spec §7.4.
///
/// Tracks the highest seen `seq` (`seq_max`) and a 256-bit bitmap of
/// seqs in the window `(seq_max - 256, seq_max]`.
#[derive(Debug, Clone)]
pub struct ReplayWindow {
    seq_max: u64,
    bitmap: [u64; 4], // 256 bits
}

impl Default for ReplayWindow {
    fn default() -> Self {
        Self::new()
    }
}

impl ReplayWindow {
    /// Empty window. The first frame on a new session bootstraps it.
    #[must_use]
    pub fn new() -> Self {
        Self {
            seq_max: 0,
            bitmap: [0; 4],
        }
    }

    /// Check + register a sequence number. Returns true if the frame
    /// should be accepted. False means it's a replay or out-of-window
    /// and MUST be silently dropped (and strike-counted at the caller).
    pub fn check_and_set(&mut self, seq: u64) -> bool {
        // Spec §7.4: outright reject implausibly large jumps.
        if seq > self.seq_max.saturating_add(1u64 << 31) {
            return false;
        }

        if seq > self.seq_max {
            // Slide window forward by `delta` bits.
            let delta = seq - self.seq_max;
            self.shift_bits(delta);
            self.seq_max = seq;
            self.set_bit(0);
            true
        } else {
            // seq <= seq_max
            let dist = self.seq_max - seq;
            if dist >= REPLAY_WINDOW {
                return false; // too old
            }
            let bit_index = dist as usize;
            if self.test_bit(bit_index) {
                false // replay
            } else {
                self.set_bit(bit_index);
                true
            }
        }
    }

    fn shift_bits(&mut self, mut n: u64) {
        // Cap at 256 — beyond that the entire window is wiped.
        if n >= REPLAY_WINDOW {
            self.bitmap = [0; 4];
            return;
        }
        while n >= 64 {
            self.bitmap.copy_within(0..3, 1);
            self.bitmap[0] = 0;
            n -= 64;
        }
        if n > 0 {
            #[allow(clippy::cast_possible_truncation)]
            let n_u = n as u32;
            // Shift the 256-bit value left by n_u bits.
            let mut carry: u64 = 0;
            for word in &mut self.bitmap {
                let new_carry = *word >> (64 - n_u);
                *word = (*word << n_u) | carry;
                carry = new_carry;
            }
        }
    }

    fn set_bit(&mut self, idx: usize) {
        self.bitmap[idx / 64] |= 1u64 << (idx % 64);
    }

    fn test_bit(&self, idx: usize) -> bool {
        (self.bitmap[idx / 64] >> (idx % 64)) & 1 == 1
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::knock_token;

    #[test]
    fn knock_accepts_current_window() {
        let mut dec = KnockDecoder::new(7);
        let k = [0x55u8; 32];
        let bucket = 100;
        let now_s = bucket * KNOCK_WINDOW_S + 1;
        let tok = knock_token(&k, 42, 7, bucket);
        let v = dec.verify(42, &[0u8; 16], &tok, now_s, |_| Some(k));
        assert_eq!(v, KnockVerdict::Accept);
    }

    #[test]
    fn knock_accepts_previous_window() {
        let mut dec = KnockDecoder::new(7);
        let k = [0x55u8; 32];
        let bucket = 100;
        let now_s = bucket * KNOCK_WINDOW_S + 1;
        let tok = knock_token(&k, 42, 7, bucket - 1);
        let v = dec.verify(42, &[0u8; 16], &tok, now_s, |_| Some(k));
        assert_eq!(v, KnockVerdict::Accept);
    }

    #[test]
    fn knock_rejects_wrong_window() {
        let mut dec = KnockDecoder::new(7);
        let k = [0x55u8; 32];
        let now_s = 3000;
        let tok = knock_token(&k, 42, 7, 50);
        let v = dec.verify(42, &[0u8; 16], &tok, now_s, |_| Some(k));
        assert_eq!(v, KnockVerdict::Drop);
    }

    #[test]
    fn knock_locks_out_after_strikes() {
        let mut dec = KnockDecoder::new(7);
        let k = [0x55u8; 32];
        let now_s = 10_000;
        let bad = [0u8; 8];
        for _ in 0..LOCKOUT_AFTER_STRIKES {
            dec.verify(42, &[0u8; 16], &bad, now_s, |_| Some(k));
        }
        assert!(dec.is_locked_out(42, now_s));
        let good_bucket = now_s / KNOCK_WINDOW_S;
        let good_tok = knock_token(&k, 42, 7, good_bucket);
        let v = dec.verify(42, &[0u8; 16], &good_tok, now_s, |_| Some(k));
        assert_eq!(v, KnockVerdict::LockedOut);
    }

    #[test]
    fn knock_unenrolled_id_does_not_strike() {
        // Important: an attacker probing a random id_a must not be able
        // to drive any *real* aircraft into lockout via collision.
        let mut dec = KnockDecoder::new(7);
        let now_s = 10_000;
        for _ in 0..LOCKOUT_AFTER_STRIKES + 5 {
            dec.verify(0xFFFF, &[0u8; 16], &[0u8; 8], now_s, |_| None);
        }
        // The unenrolled id has no record => should report not-locked.
        assert!(!dec.is_locked_out(0xFFFF, now_s));
    }

    #[test]
    fn replay_window_basics() {
        let mut w = ReplayWindow::new();
        assert!(w.check_and_set(1));
        assert!(w.check_and_set(2));
        // replay
        assert!(!w.check_and_set(1));
        assert!(!w.check_and_set(2));
        // jump forward
        assert!(w.check_and_set(100));
        assert!(!w.check_and_set(100));
    }

    #[test]
    fn replay_window_drops_too_old() {
        let mut w = ReplayWindow::new();
        assert!(w.check_and_set(500));
        // 500 - 256 = 244, anything <= 244 is too old
        assert!(!w.check_and_set(100));
        assert!(!w.check_and_set(244));
        assert!(w.check_and_set(245));
    }

    #[test]
    fn replay_window_rejects_huge_jump() {
        let mut w = ReplayWindow::new();
        assert!(w.check_and_set(1));
        assert!(!w.check_and_set(1u64 << 40));
    }
}
