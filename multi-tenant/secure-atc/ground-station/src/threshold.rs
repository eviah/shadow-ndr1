//! Threshold ML-DSA signing trait (frontier upgrade #4).
//!
//! Production HSMs sit behind a coordinator that runs the **DKLs23**
//! threshold ML-DSA protocol. This module declares the interface
//! `ThresholdSigner` so callers can swap the production threshold
//! signer in without touching protocol code. The current concrete
//! implementation is a 1-of-1 proxy to `Hsm::sign_with_ground` — the
//! same sigma-or-not interface that DKLs23 will provide.

use crate::hsm::{Hsm, HsmError};

/// One holder's share of a threshold sign.
#[derive(Clone)]
pub struct SignShard {
    pub holder: u8,
    pub bytes: Vec<u8>,
}

/// A threshold signer over the ground long-term key.
pub trait ThresholdSigner {
    /// Total shares (n).
    fn shares(&self) -> u8;
    /// Reconstruction threshold (t).
    fn threshold(&self) -> u8;
    /// Produce one holder's signing shard for `payload`.
    fn sign_shard(&self, holder: u8, payload: &[u8]) -> Result<SignShard, HsmError>;
    /// Combine `t` shards into a single signature.
    fn combine(&self, shards: &[SignShard], payload: &[u8]) -> Result<Vec<u8>, HsmError>;
}

/// 1-of-1 specialization: the existing single HSM. Useful as a stub
/// while a real DKLs23 implementation is integrated; production
/// configurations supply their own `ThresholdSigner` impl.
pub struct SingleSigner<'a> {
    pub hsm: &'a Hsm,
}

impl<'a> ThresholdSigner for SingleSigner<'a> {
    fn shares(&self) -> u8 {
        1
    }
    fn threshold(&self) -> u8 {
        1
    }
    fn sign_shard(&self, holder: u8, payload: &[u8]) -> Result<SignShard, HsmError> {
        if holder != 1 {
            return Err(HsmError::NotEnrolled);
        }
        Ok(SignShard {
            holder,
            bytes: self.hsm.sign_with_ground(payload)?,
        })
    }
    fn combine(&self, shards: &[SignShard], _payload: &[u8]) -> Result<Vec<u8>, HsmError> {
        if shards.len() != 1 {
            return Err(HsmError::BadSignature);
        }
        Ok(shards[0].bytes.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn single_signer_round_trip() {
        let hsm = Hsm::boot();
        let signer = SingleSigner { hsm: &hsm };
        let shard = signer.sign_shard(1, b"hello").expect("shard");
        let sig = signer.combine(&[shard], b"hello").expect("combine");
        assert!(!sig.is_empty());
    }

    #[test]
    fn single_signer_rejects_unknown_holder() {
        let hsm = Hsm::boot();
        let signer = SingleSigner { hsm: &hsm };
        let r = signer.sign_shard(2, b"x");
        assert!(r.is_err());
    }
}
