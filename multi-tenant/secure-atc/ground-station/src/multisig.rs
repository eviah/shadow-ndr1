//! Triple-signature wrapper (frontier upgrade #3).
//!
//! Wire format:
//! ```text
//!   mask:  u8                       (bit 0 = ML-DSA, 1 = XMSS, 2 = SPHINCS+)
//!   for each set bit, in ascending order:
//!       len:  u32 BE
//!       sig:  bytes[len]
//! ```
//!
//! A frame validates if the `mask` byte is included in the canonical
//! signed-bytes (so an attacker cannot strip a sig kind without
//! invalidating every remaining signature) AND **at least one present
//! signature verifies** under the corresponding ground long-term key.
//!
//! XMSS and SPHINCS+ providers are wired but currently return
//! [`SigError::ProviderMissing`] until pure-Rust impls are pulled in.
//! ML-DSA is fully functional via the existing HSM.

use ml_dsa::{
    signature::{Signer, Verifier},
    EncodedSignature, KeyPair, MlDsa87, Signature, VerifyingKey,
};

/// Signature family tags. Match the wire bit positions in `mask`.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum SigKind {
    MlDsa = 0x01,
    Xmss = 0x02,
    SphincsPlus = 0x04,
}

impl SigKind {
    pub fn bit(self) -> u8 {
        self as u8
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum SigError {
    /// No provider has been registered for this kind.
    ProviderMissing,
    /// Bytes failed parse.
    Malformed,
    /// At least one sig was present and none verified.
    AllInvalid,
    /// `mask` had no bits set.
    Empty,
}

/// One signature share over the same canonical bytes.
#[derive(Clone, Debug)]
pub struct OneSig {
    pub kind: SigKind,
    pub bytes: Vec<u8>,
}

/// Container for up to three signatures over identical signed bytes.
#[derive(Clone, Debug, Default)]
pub struct MultiSig {
    pub sigs: Vec<OneSig>,
}

impl MultiSig {
    pub fn new() -> Self {
        Self { sigs: Vec::new() }
    }

    pub fn push(&mut self, kind: SigKind, bytes: Vec<u8>) {
        self.sigs.push(OneSig { kind, bytes });
    }

    /// Compute the wire `mask` byte.
    pub fn mask(&self) -> u8 {
        self.sigs.iter().fold(0u8, |a, s| a | s.kind.bit())
    }

    /// Serialize to wire bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.push(self.mask());
        // Ascending-bit order so encoders match decoders deterministically.
        for kind_bit in [SigKind::MlDsa, SigKind::Xmss, SigKind::SphincsPlus] {
            if let Some(s) = self.sigs.iter().find(|s| s.kind == kind_bit) {
                out.extend_from_slice(&(s.bytes.len() as u32).to_be_bytes());
                out.extend_from_slice(&s.bytes);
            }
        }
        out
    }

    /// Parse from wire bytes. Returns the parsed struct AND the number
    /// of bytes consumed, so callers can locate trailing data.
    pub fn from_bytes(b: &[u8]) -> Result<(Self, usize), SigError> {
        if b.is_empty() {
            return Err(SigError::Malformed);
        }
        let mask = b[0];
        if mask == 0 {
            return Err(SigError::Empty);
        }
        let mut idx = 1usize;
        let mut sigs = Vec::new();
        for kind_bit in [SigKind::MlDsa, SigKind::Xmss, SigKind::SphincsPlus] {
            if mask & kind_bit.bit() != 0 {
                if idx + 4 > b.len() {
                    return Err(SigError::Malformed);
                }
                let len = u32::from_be_bytes(b[idx..idx + 4].try_into().unwrap()) as usize;
                idx += 4;
                if idx + len > b.len() {
                    return Err(SigError::Malformed);
                }
                sigs.push(OneSig {
                    kind: kind_bit,
                    bytes: b[idx..idx + len].to_vec(),
                });
                idx += len;
            }
        }
        Ok((Self { sigs }, idx))
    }
}

/// Verifier dispatcher. Holds the public keys for each sig kind and
/// returns success if **any one** registered provider verifies.
pub struct MultiSigVerifier {
    pub ml_dsa: Option<VerifyingKey<MlDsa87>>,
    /// XMSS public key bytes — provider currently rejects all sigs.
    pub xmss_pk: Option<Vec<u8>>,
    /// SPHINCS+ public key bytes — provider currently rejects all sigs.
    pub sphincs_pk: Option<Vec<u8>>,
}

impl MultiSigVerifier {
    pub fn ml_dsa_only(vk: VerifyingKey<MlDsa87>) -> Self {
        Self {
            ml_dsa: Some(vk),
            xmss_pk: None,
            sphincs_pk: None,
        }
    }

    /// Returns Ok(()) if at least one signature in `ms` verifies under the
    /// corresponding registered key. The caller is responsible for
    /// including `ms.mask()` in `signed_bytes` (anti-downgrade).
    ///
    /// Error precedence: if any sig verified `AllInvalid`, that's the
    /// returned error. Else if every present sig had a missing
    /// provider, returns `ProviderMissing`.
    pub fn verify(&self, ms: &MultiSig, signed_bytes: &[u8]) -> Result<(), SigError> {
        if ms.sigs.is_empty() {
            return Err(SigError::Empty);
        }
        let mut saw_invalid = false;
        for sig in &ms.sigs {
            let ok = match sig.kind {
                SigKind::MlDsa => self.verify_ml_dsa(&sig.bytes, signed_bytes),
                SigKind::Xmss => self.verify_xmss(&sig.bytes, signed_bytes),
                SigKind::SphincsPlus => self.verify_sphincs(&sig.bytes, signed_bytes),
            };
            match ok {
                Ok(()) => return Ok(()),
                Err(SigError::AllInvalid) => saw_invalid = true,
                Err(_) => {}
            }
        }
        if saw_invalid {
            Err(SigError::AllInvalid)
        } else {
            Err(SigError::ProviderMissing)
        }
    }

    fn verify_ml_dsa(&self, sig: &[u8], msg: &[u8]) -> Result<(), SigError> {
        let vk = self.ml_dsa.as_ref().ok_or(SigError::ProviderMissing)?;
        let encoded: EncodedSignature<MlDsa87> =
            sig.try_into().map_err(|_| SigError::Malformed)?;
        let parsed = Signature::<MlDsa87>::decode(&encoded).ok_or(SigError::Malformed)?;
        vk.verify(msg, &parsed).map_err(|_| SigError::AllInvalid)
    }

    fn verify_xmss(&self, _sig: &[u8], _msg: &[u8]) -> Result<(), SigError> {
        // Provider hook: real XMSS verifier slot in here. Until then,
        // fail closed.
        if self.xmss_pk.is_none() {
            return Err(SigError::ProviderMissing);
        }
        Err(SigError::ProviderMissing)
    }

    fn verify_sphincs(&self, _sig: &[u8], _msg: &[u8]) -> Result<(), SigError> {
        if self.sphincs_pk.is_none() {
            return Err(SigError::ProviderMissing);
        }
        Err(SigError::ProviderMissing)
    }
}

/// Helper: sign with ML-DSA. The other kinds slot in alongside in
/// production builds.
pub fn sign_ml_dsa(kp: &KeyPair<MlDsa87>, msg: &[u8]) -> Vec<u8> {
    let sig: Signature<MlDsa87> = kp.signing_key().sign(msg);
    sig.encode().to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;
    use ml_dsa::KeyGen;
    use rand::rngs::OsRng;

    fn signed_with_mask(mask: u8, payload: &[u8]) -> Vec<u8> {
        let mut v = Vec::with_capacity(1 + payload.len());
        v.push(mask);
        v.extend_from_slice(payload);
        v
    }

    #[test]
    fn round_trip_one_sig() {
        let kp = MlDsa87::key_gen(&mut OsRng);
        let mut ms = MultiSig::new();
        // Compute the mask first (since the signed-bytes include it).
        let mask = SigKind::MlDsa.bit();
        let signed = signed_with_mask(mask, b"hello");
        let sig_bytes = sign_ml_dsa(&kp, &signed);
        ms.push(SigKind::MlDsa, sig_bytes);
        assert_eq!(ms.mask(), mask);

        let verifier = MultiSigVerifier::ml_dsa_only(kp.verifying_key().clone());
        verifier.verify(&ms, &signed).expect("any-of-three");
    }

    #[test]
    fn wire_round_trip() {
        let kp = MlDsa87::key_gen(&mut OsRng);
        let mut ms = MultiSig::new();
        let signed = signed_with_mask(SigKind::MlDsa.bit(), b"payload");
        ms.push(SigKind::MlDsa, sign_ml_dsa(&kp, &signed));

        let bytes = ms.to_bytes();
        let (parsed, n) = MultiSig::from_bytes(&bytes).expect("parse");
        assert_eq!(n, bytes.len());
        assert_eq!(parsed.mask(), ms.mask());
        assert_eq!(parsed.sigs.len(), 1);
        assert_eq!(parsed.sigs[0].kind, SigKind::MlDsa);
    }

    #[test]
    fn empty_mask_rejected() {
        let bytes = vec![0x00u8];
        let r = MultiSig::from_bytes(&bytes);
        assert_eq!(r.err(), Some(SigError::Empty));
    }

    #[test]
    fn xmss_provider_missing_when_only_xmss_present() {
        let mut ms = MultiSig::new();
        ms.push(SigKind::Xmss, vec![0u8; 32]);
        let verifier = MultiSigVerifier {
            ml_dsa: None,
            xmss_pk: None,
            sphincs_pk: None,
        };
        let signed = signed_with_mask(SigKind::Xmss.bit(), b"x");
        let r = verifier.verify(&ms, &signed);
        assert_eq!(r.err(), Some(SigError::ProviderMissing));
    }

    #[test]
    fn any_one_valid_sig_accepts() {
        // Two ML-DSA keys: one bogus sig, one real. The real one is
        // sufficient. We use distinct kinds so the wire format admits both.
        let kp = MlDsa87::key_gen(&mut OsRng);
        let mask = SigKind::MlDsa.bit() | SigKind::Xmss.bit();
        let signed = signed_with_mask(mask, b"payload");

        let mut ms = MultiSig::new();
        // The XMSS sig is junk; the verifier slot for XMSS is missing.
        ms.push(SigKind::Xmss, vec![0u8; 16]);
        // The ML-DSA sig is valid.
        ms.push(SigKind::MlDsa, sign_ml_dsa(&kp, &signed));

        let verifier = MultiSigVerifier::ml_dsa_only(kp.verifying_key().clone());
        verifier.verify(&ms, &signed).expect("ML-DSA path saves us");
    }

    #[test]
    fn all_invalid_rejects() {
        let kp1 = MlDsa87::key_gen(&mut OsRng);
        let kp2 = MlDsa87::key_gen(&mut OsRng);
        let signed = signed_with_mask(SigKind::MlDsa.bit(), b"payload");
        // Sign with kp1 but verify with kp2.
        let mut ms = MultiSig::new();
        ms.push(SigKind::MlDsa, sign_ml_dsa(&kp1, &signed));
        let verifier = MultiSigVerifier::ml_dsa_only(kp2.verifying_key().clone());
        let r = verifier.verify(&ms, &signed);
        assert_eq!(r.err(), Some(SigError::AllInvalid));
    }
}
