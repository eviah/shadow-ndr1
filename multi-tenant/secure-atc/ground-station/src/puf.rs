//! Physically Unclonable Function (frontier upgrade #15).
//!
//! Trait `PufSource` returns a 32-byte challenge-response whose
//! distribution is a function of *manufacturing variation* in the
//! silicon. Because that variation is unique to the die and cannot
//! be cloned, capturing all stored secrets does NOT let an attacker
//! impersonate the device.
//!
//! Production providers wrap the on-die SRAM-PUF or RO-PUF macro;
//! the [`HashedIdPuf`] here is purely for tests.

use sha3::{Digest, Sha3_256};

pub trait PufSource {
    /// Derive a 32-byte response for the given challenge.
    fn respond(&self, challenge: &[u8]) -> [u8; 32];
}

/// Test fixture: SHA3 over the device id and the challenge. Production
/// builds replace this with the silicon PUF macro.
pub struct HashedIdPuf {
    pub device_id: [u8; 32],
}

impl PufSource for HashedIdPuf {
    fn respond(&self, challenge: &[u8]) -> [u8; 32] {
        let mut h = Sha3_256::new();
        h.update(b"shadow-comm/v1/puf-test-stub");
        h.update(self.device_id);
        h.update(challenge);
        let out = h.finalize();
        let mut r = [0u8; 32];
        r.copy_from_slice(&out);
        r
    }
}

/// Derive a fresh `k_master` from the PUF response and a server-provided
/// challenge. The challenge is public; only the PUF response is secret.
pub fn derive_k_master_from_puf(puf: &dyn PufSource, challenge: &[u8]) -> [u8; 32] {
    let mut h = Sha3_256::new();
    h.update(b"shadow-comm/v1/k_master-from-puf");
    h.update(puf.respond(challenge));
    h.update(challenge);
    let out = h.finalize();
    let mut k = [0u8; 32];
    k.copy_from_slice(&out);
    k
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn distinct_devices_produce_distinct_keys() {
        let p1 = HashedIdPuf { device_id: [1u8; 32] };
        let p2 = HashedIdPuf { device_id: [2u8; 32] };
        let k1 = derive_k_master_from_puf(&p1, b"chal");
        let k2 = derive_k_master_from_puf(&p2, b"chal");
        assert_ne!(k1, k2);
    }

    #[test]
    fn same_device_same_challenge_is_deterministic() {
        let p = HashedIdPuf { device_id: [9u8; 32] };
        let k1 = derive_k_master_from_puf(&p, b"chal");
        let k2 = derive_k_master_from_puf(&p, b"chal");
        assert_eq!(k1, k2);
    }
}
