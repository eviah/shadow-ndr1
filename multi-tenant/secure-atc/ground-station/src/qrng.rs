//! Quantum Random Number Generator hook (frontier upgrade #13).
//!
//! Trait `QrngSource` is filled by a real QRNG device in production
//! (ID Quantique Quantis, Quside QN100, on-die module of the HSM, etc).
//! The reference implementation defaults to OsRng — adequate for tests
//! but not certified.
//!
//! Callers route ALL nonce/key/blinding randomness through this trait
//! when QRNG is required by policy. The HSM driver verifies the
//! provenance before allowing the bytes to feed key generation.

use rand::rngs::OsRng;
use rand::RngCore;

pub trait QrngSource {
    /// Fill `dst` with QRNG bytes.
    fn fill(&mut self, dst: &mut [u8]);
}

/// Default implementation backed by OsRng. Suitable for tests; flagged
/// in production as `qrng=fallback` so the monitoring plane logs every
/// session that derived randomness from a non-quantum source.
pub struct OsRngQrng;

impl QrngSource for OsRngQrng {
    fn fill(&mut self, dst: &mut [u8]) {
        OsRng.fill_bytes(dst);
    }
}

/// Mixing wrapper: XORs a QRNG block into a CSPRNG block. Defense in
/// depth — even if either source is biased, the result preserves the
/// other's entropy.
pub struct MixedQrng<'a, Q: QrngSource> {
    pub quantum: &'a mut Q,
}

impl<'a, Q: QrngSource> QrngSource for MixedQrng<'a, Q> {
    fn fill(&mut self, dst: &mut [u8]) {
        self.quantum.fill(dst);
        let mut classical = vec![0u8; dst.len()];
        OsRng.fill_bytes(&mut classical);
        for (a, b) in dst.iter_mut().zip(classical.iter()) {
            *a ^= *b;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn os_rng_qrng_produces_nonzero_output() {
        let mut q = OsRngQrng;
        let mut buf = [0u8; 32];
        q.fill(&mut buf);
        assert!(buf.iter().any(|&b| b != 0));
    }

    #[test]
    fn mixed_changes_distribution() {
        struct ZeroQrng;
        impl QrngSource for ZeroQrng {
            fn fill(&mut self, dst: &mut [u8]) {
                for b in dst.iter_mut() {
                    *b = 0;
                }
            }
        }
        let mut q = ZeroQrng;
        let mut mixed = MixedQrng { quantum: &mut q };
        let mut buf = [0u8; 32];
        mixed.fill(&mut buf);
        // Mixed with classical OsRng — should still have nonzero bytes.
        assert!(buf.iter().any(|&b| b != 0));
    }
}
