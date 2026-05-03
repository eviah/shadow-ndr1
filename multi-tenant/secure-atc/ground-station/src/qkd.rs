//! Hybrid post-quantum + Quantum Key Distribution (frontier upgrade #1).
//!
//! On the inter-site trunk, a BB84 (or E91, or MDI) device delivers
//! 32-byte secret blocks to each end. We XOR that block into the HKDF
//! salt of the Phase-3 derivation. Even if both ML-KEM and ML-DSA fall,
//! the salt entropy that comes from physical quantum mechanics keeps
//! the session keys secret.
//!
//! When no QKD device is wired in, [`QkdKey::ZERO`] is used — bit-for-bit
//! compatible with SHADOW-COMM v1.

use zeroize::Zeroizing;

/// 32-byte chunk of QKD key material.
#[derive(Clone)]
pub struct QkdKey(pub Zeroizing<[u8; 32]>);

impl QkdKey {
    /// All-zero block. Use this when no QKD is available — the XOR
    /// becomes a no-op and the protocol degrades to vanilla v1.
    pub const ZERO_BYTES: [u8; 32] = [0u8; 32];

    pub fn zero() -> Self {
        Self(Zeroizing::new(Self::ZERO_BYTES))
    }

    pub fn from_bytes(b: [u8; 32]) -> Self {
        Self(Zeroizing::new(b))
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// XOR `self` into the first 32 bytes of `dst` in place.
    pub fn xor_into(&self, dst: &mut [u8]) {
        let n = dst.len().min(32);
        for i in 0..n {
            dst[i] ^= self.0[i];
        }
    }
}

/// Source of QKD key blocks. The trunk integration polls this once per
/// rekey window; the implementation is responsible for QBER monitoring,
/// privacy amplification, and refusing to deliver bytes if the link
/// quality dropped below the configured threshold.
pub trait QkdKeySource {
    /// Pull one fresh 32-byte block, or `None` if the link is currently
    /// unhealthy (in which case the caller MUST use [`QkdKey::zero`]
    /// and surface the degraded state to monitoring).
    fn next_key(&mut self) -> Option<QkdKey>;
}

/// Test/dev implementation that always returns the zero block. The
/// session derived with this is identical to v1.
pub struct NullQkd;

impl QkdKeySource for NullQkd {
    fn next_key(&mut self) -> Option<QkdKey> {
        Some(QkdKey::zero())
    }
}

/// Test fixture: returns a deterministic block. NEVER use in production.
pub struct FixedQkd(pub [u8; 32]);

impl QkdKeySource for FixedQkd {
    fn next_key(&mut self) -> Option<QkdKey> {
        Some(QkdKey::from_bytes(self.0))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn xor_into_no_op_when_zero() {
        let k = QkdKey::zero();
        let mut buf = [0xABu8; 32];
        k.xor_into(&mut buf);
        assert_eq!(buf, [0xABu8; 32]);
    }

    #[test]
    fn xor_into_flips_bits() {
        let k = QkdKey::from_bytes([0xFFu8; 32]);
        let mut buf = [0xABu8; 32];
        k.xor_into(&mut buf);
        assert_eq!(buf, [0xABu8 ^ 0xFFu8; 32]);
    }

    #[test]
    fn xor_into_truncates_short_buffer() {
        let k = QkdKey::from_bytes([0xFFu8; 32]);
        let mut buf = [0u8; 8];
        k.xor_into(&mut buf);
        assert_eq!(buf, [0xFFu8; 8]);
    }
}
