//! Sequential proof for replay-window timing (frontier upgrade #9).
//!
//! ## What this is
//!
//! A sequential SHA3-256 hash chain. The producer evaluates `n` rounds
//! of `out = SHA3-256(out)`; the verifier replays the chain. Each
//! frame's proof anchors to the frame's seq + a session salt, so
//! replays in a different order or after a long delay are rejected.
//!
//! ## What this is NOT
//!
//! Not a true VDF. Verification cost equals computation cost — there
//! is no asymmetric speedup. A true Wesolowski / Pietrzak VDF requires
//! BigInt arithmetic over class groups, which is out of our offline
//! crate set. The trait [`SeqProof`] is designed so a real VDF drops
//! in unchanged when the BigInt dependency is added.
//!
//! For the SHADOW-COMM use case — bounding how long an attacker can
//! sit on a captured frame before replaying it — a hash chain is
//! sufficient: we calibrate `n` so the chain takes longer than the
//! tolerated transit delay, and the same hardware floor that bounds
//! the attacker also bounds the legitimate producer.

use sha3::{Digest, Sha3_256};

pub trait SeqProof {
    fn compute(input: &[u8; 32], iterations: u64) -> [u8; 32];
    fn verify(input: &[u8; 32], iterations: u64, output: &[u8; 32]) -> bool;
}

pub struct HashChain;

impl SeqProof for HashChain {
    fn compute(input: &[u8; 32], iterations: u64) -> [u8; 32] {
        let mut state = *input;
        for _ in 0..iterations {
            let mut h = Sha3_256::new();
            h.update(b"shadow-comm/v1/seqproof");
            h.update(state);
            let out = h.finalize();
            state.copy_from_slice(&out);
        }
        state
    }

    fn verify(input: &[u8; 32], iterations: u64, output: &[u8; 32]) -> bool {
        let recomputed = Self::compute(input, iterations);
        // Constant-time over the output bytes.
        use subtle::ConstantTimeEq;
        recomputed.ct_eq(output).into()
    }
}

/// Anchor `seq` and a session salt into the seed of the hash chain.
pub fn seed_for(salt: &[u8; 32], seq: u64) -> [u8; 32] {
    let mut h = Sha3_256::new();
    h.update(b"shadow-comm/v1/seqproof/seed");
    h.update(salt);
    h.update(seq.to_be_bytes());
    let out = h.finalize();
    let mut s = [0u8; 32];
    s.copy_from_slice(&out);
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip() {
        let input = [0x42u8; 32];
        let out = HashChain::compute(&input, 1024);
        assert!(HashChain::verify(&input, 1024, &out));
    }

    #[test]
    fn wrong_iterations_rejects() {
        let input = [0x42u8; 32];
        let out = HashChain::compute(&input, 1024);
        assert!(!HashChain::verify(&input, 1023, &out));
        assert!(!HashChain::verify(&input, 1025, &out));
    }

    #[test]
    fn different_input_rejects() {
        let input = [0x42u8; 32];
        let other = [0x43u8; 32];
        let out = HashChain::compute(&input, 100);
        assert!(!HashChain::verify(&other, 100, &out));
    }

    #[test]
    fn seed_changes_with_seq() {
        let salt = [0x77u8; 32];
        let s1 = seed_for(&salt, 1);
        let s2 = seed_for(&salt, 2);
        assert_ne!(s1, s2);
    }

    #[test]
    fn zero_iterations_is_identity() {
        let input = [0xAAu8; 32];
        let out = HashChain::compute(&input, 0);
        assert_eq!(out, input);
    }
}
