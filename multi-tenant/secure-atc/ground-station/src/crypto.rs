//! Crypto primitives used by the ground-station daemon.
//!
//! All wrappers route through vetted RustCrypto implementations:
//! `aes-gcm`, `sha3`, `hkdf`, `hmac`. Keys are wrapped in [`zeroize::Zeroizing`]
//! containers so they are wiped on drop — see spec §6 (Phase 4) for the
//! requirement that the previous session key is `memset_explicit`'d.
//!
//! Secret comparisons use [`subtle::ConstantTimeEq`].

use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
    Aes256Gcm, Nonce,
};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha3::{Sha3_256, Sha3_512};
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, Zeroizing};

use crate::protocol::{
    AEAD_IV_LEN, AEAD_KEY_LEN, AEAD_TAG_LEN, KEM_SHARED_LEN, KNOCK_TOKEN_LEN, NONCE_LEN,
};

/// Errors surfaced by the crypto layer.
///
/// We deliberately do not distinguish AEAD-internal failure modes — that
/// would be an oracle. Spec §10 maps every cryptographic failure to a
/// silent drop on the operational plane.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum CryptoError {
    /// AEAD decryption (or encryption) failed.
    Aead,
    /// Output buffer was the wrong size, or input was malformed.
    Length,
}

/// HMAC-SHA3-256 truncated to 8 bytes — the wire knock token.
///
/// Spec §3.1: `HMAC-SHA3-256(K_master[A], "SHADOW-COMM/v1/knock" || id_A
/// || id_G || U64BE(B))[:8]`.
#[must_use]
pub fn knock_token(
    k_master: &[u8; 32],
    id_a: u64,
    id_g: u32,
    bucket: u64,
) -> [u8; KNOCK_TOKEN_LEN] {
    type HmacSha3_256 = Hmac<Sha3_256>;

    let mut mac =
        <HmacSha3_256 as Mac>::new_from_slice(k_master).expect("HMAC accepts any key length");
    mac.update(b"SHADOW-COMM/v1/knock");
    mac.update(&id_a.to_be_bytes());
    mac.update(&id_g.to_be_bytes());
    mac.update(&bucket.to_be_bytes());
    let full = mac.finalize().into_bytes();
    let mut out = [0u8; KNOCK_TOKEN_LEN];
    out.copy_from_slice(&full[..KNOCK_TOKEN_LEN]);
    out
}

/// Constant-time equality on the 8-byte knock token.
///
/// Spec §3.3 step 1: compare against both `B` and `B-1`, constant time.
#[must_use]
pub fn knock_eq(a: &[u8; KNOCK_TOKEN_LEN], b: &[u8; KNOCK_TOKEN_LEN]) -> bool {
    a.ct_eq(b).into()
}

/// HKDF-SHA3-512: extract `prk` from `(salt, ikm)`.
#[must_use]
pub fn hkdf_extract(salt: &[u8], ikm: &[u8]) -> Hkdf<Sha3_512> {
    Hkdf::<Sha3_512>::new(Some(salt), ikm)
}

/// HKDF-Expand a single labelled output of length `N`.
///
/// Used for the four session derivations in spec §6.
pub fn hkdf_expand<const N: usize>(prk: &Hkdf<Sha3_512>, info: &[u8]) -> [u8; N] {
    let mut out = [0u8; N];
    prk.expand(info, &mut out).expect("HKDF length within limits");
    out
}

/// Session keys derived from the KEM shared secret (spec §6).
///
/// Held in a zeroizing wrapper; drop wipes the bytes.
pub struct SessionKeys {
    /// Aircraft → Ground AES-256-GCM key.
    pub k_ag: Zeroizing<[u8; AEAD_KEY_LEN]>,
    /// Ground → Aircraft AES-256-GCM key.
    pub k_ga: Zeroizing<[u8; AEAD_KEY_LEN]>,
    /// Aircraft → Ground IV base.
    pub iv_ag: Zeroizing<[u8; AEAD_IV_LEN]>,
    /// Ground → Aircraft IV base.
    pub iv_ga: Zeroizing<[u8; AEAD_IV_LEN]>,
}

impl SessionKeys {
    /// Derive both directions' keys + IV bases from the KEM secret + nonces.
    ///
    /// Spec §6.
    #[must_use]
    pub fn derive(
        ss: &[u8; KEM_SHARED_LEN],
        nonce_a: &[u8; NONCE_LEN],
        nonce_g: &[u8; NONCE_LEN],
        id_a: u64,
        id_g: u32,
    ) -> Self {
        Self::derive_with_qkd(ss, nonce_a, nonce_g, id_a, id_g, &[0u8; 32])
    }

    /// Hybrid PQ + QKD derivation (frontier upgrade #1).
    ///
    /// Identical to [`derive`](Self::derive) when `qkd_key` is all-zero.
    /// Otherwise the 32-byte QKD block is XOR'd into the 64-byte HKDF
    /// salt before extraction, so an attacker who breaks ML-KEM still
    /// faces the QKD entropy when trying to recover session keys.
    #[must_use]
    pub fn derive_with_qkd(
        ss: &[u8; KEM_SHARED_LEN],
        nonce_a: &[u8; NONCE_LEN],
        nonce_g: &[u8; NONCE_LEN],
        id_a: u64,
        id_g: u32,
        qkd_key: &[u8; 32],
    ) -> Self {
        use sha3::Digest;
        let mut salt_in = [0u8; NONCE_LEN * 2];
        salt_in[..NONCE_LEN].copy_from_slice(nonce_a);
        salt_in[NONCE_LEN..].copy_from_slice(nonce_g);
        let mut salt = [0u8; 64];
        salt.copy_from_slice(&Sha3_512::digest(salt_in));
        for i in 0..32 {
            salt[i] ^= qkd_key[i];
        }

        let prk = hkdf_extract(&salt, ss);

        let info_ag_k = make_info(b"SHADOW-COMM/v1/A->G/key", id_a, id_g);
        let info_ga_k = make_info(b"SHADOW-COMM/v1/G->A/key", id_a, id_g);
        let info_ag_i = make_info(b"SHADOW-COMM/v1/A->G/iv", id_a, id_g);
        let info_ga_i = make_info(b"SHADOW-COMM/v1/G->A/iv", id_a, id_g);

        Self {
            k_ag: Zeroizing::new(hkdf_expand::<AEAD_KEY_LEN>(&prk, &info_ag_k)),
            k_ga: Zeroizing::new(hkdf_expand::<AEAD_KEY_LEN>(&prk, &info_ga_k)),
            iv_ag: Zeroizing::new(hkdf_expand::<AEAD_IV_LEN>(&prk, &info_ag_i)),
            iv_ga: Zeroizing::new(hkdf_expand::<AEAD_IV_LEN>(&prk, &info_ga_i)),
        }
    }
}

/// Direction tag — used to pick the right key/IV pair.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Direction {
    /// Aircraft → Ground.
    AircraftToGround,
    /// Ground → Aircraft.
    GroundToAircraft,
}

/// Combine the IV base with a 64-bit `seq` per spec §6:
///
/// `IV_dir XOR (4 zero bytes || U64BE(seq))`.
#[must_use]
fn iv_for(iv_base: &[u8; AEAD_IV_LEN], seq: u64) -> [u8; AEAD_IV_LEN] {
    let mut iv = *iv_base;
    let s = seq.to_be_bytes();
    iv[4..].iter_mut().zip(s.iter()).for_each(|(a, b)| *a ^= *b);
    iv
}

/// Encrypt a Phase-5 data frame (spec §7.2).
///
/// Returns `(ciphertext, tag)` separately so the caller can lay them
/// out per the frame format.
pub fn aead_seal(
    keys: &SessionKeys,
    dir: Direction,
    seq: u64,
    aad: &[u8],
    plaintext: &[u8],
) -> Result<(Vec<u8>, [u8; AEAD_TAG_LEN]), CryptoError> {
    let (key, iv_base) = match dir {
        Direction::AircraftToGround => (&keys.k_ag, &keys.iv_ag),
        Direction::GroundToAircraft => (&keys.k_ga, &keys.iv_ga),
    };
    let iv = iv_for(iv_base, seq);
    let cipher = Aes256Gcm::new_from_slice(key.as_slice()).map_err(|_| CryptoError::Length)?;
    let nonce = Nonce::from_slice(&iv);
    let combined = cipher
        .encrypt(nonce, Payload { msg: plaintext, aad })
        .map_err(|_| CryptoError::Aead)?;

    if combined.len() < AEAD_TAG_LEN {
        return Err(CryptoError::Length);
    }
    let split = combined.len() - AEAD_TAG_LEN;
    let mut tag = [0u8; AEAD_TAG_LEN];
    tag.copy_from_slice(&combined[split..]);
    let mut ciphertext = combined;
    ciphertext.truncate(split);
    Ok((ciphertext, tag))
}

/// Decrypt a Phase-5 data frame (spec §7.3).
pub fn aead_open(
    keys: &SessionKeys,
    dir: Direction,
    seq: u64,
    aad: &[u8],
    ciphertext: &[u8],
    tag: &[u8; AEAD_TAG_LEN],
) -> Result<Vec<u8>, CryptoError> {
    let (key, iv_base) = match dir {
        Direction::AircraftToGround => (&keys.k_ag, &keys.iv_ag),
        Direction::GroundToAircraft => (&keys.k_ga, &keys.iv_ga),
    };
    let iv = iv_for(iv_base, seq);
    let cipher = Aes256Gcm::new_from_slice(key.as_slice()).map_err(|_| CryptoError::Length)?;
    let nonce = Nonce::from_slice(&iv);

    let mut combined = Vec::with_capacity(ciphertext.len() + AEAD_TAG_LEN);
    combined.extend_from_slice(ciphertext);
    combined.extend_from_slice(tag);

    cipher
        .decrypt(nonce, Payload { msg: &combined, aad })
        .map_err(|_| CryptoError::Aead)
}

fn make_info(label: &[u8], id_a: u64, id_g: u32) -> Vec<u8> {
    let mut v = Vec::with_capacity(label.len() + 8 + 4);
    v.extend_from_slice(label);
    v.extend_from_slice(&id_a.to_be_bytes());
    v.extend_from_slice(&id_g.to_be_bytes());
    v
}

/// Forcefully wipe a 32-byte buffer. Used after the previous-rekey key
/// has been replaced (spec §5b step 3).
pub fn explicit_wipe(buf: &mut [u8]) {
    buf.zeroize();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn knock_token_is_deterministic_and_window_sensitive() {
        let k = [0x42u8; 32];
        let a = knock_token(&k, 1, 2, 100);
        let b = knock_token(&k, 1, 2, 100);
        let c = knock_token(&k, 1, 2, 101);
        assert!(knock_eq(&a, &b));
        assert!(!knock_eq(&a, &c));
    }

    #[test]
    fn knock_token_changes_with_id() {
        let k = [0u8; 32];
        let a = knock_token(&k, 1, 2, 100);
        let b = knock_token(&k, 1, 3, 100);
        let c = knock_token(&k, 9, 2, 100);
        assert!(!knock_eq(&a, &b));
        assert!(!knock_eq(&a, &c));
    }

    #[test]
    fn aead_round_trip() {
        let ss = [0x77u8; KEM_SHARED_LEN];
        let na = [0x11u8; NONCE_LEN];
        let ng = [0x22u8; NONCE_LEN];
        let keys = SessionKeys::derive(&ss, &na, &ng, 0xAABB, 0xCCDD);

        let aad = b"header-as-aad";
        let pt = b"hello atc";
        let (ct, tag) =
            aead_seal(&keys, Direction::AircraftToGround, 1, aad, pt).expect("seal");
        let opened =
            aead_open(&keys, Direction::AircraftToGround, 1, aad, &ct, &tag).expect("open");
        assert_eq!(opened, pt);
    }

    #[test]
    fn aead_rejects_seq_mismatch() {
        let ss = [0x77u8; KEM_SHARED_LEN];
        let na = [0x11u8; NONCE_LEN];
        let ng = [0x22u8; NONCE_LEN];
        let keys = SessionKeys::derive(&ss, &na, &ng, 0xAABB, 0xCCDD);
        let aad = b"x";
        let (ct, tag) =
            aead_seal(&keys, Direction::AircraftToGround, 1, aad, b"y").expect("seal");
        // Caller pretends seq 2 — IV differs, AEAD must reject.
        let r = aead_open(&keys, Direction::AircraftToGround, 2, aad, &ct, &tag);
        assert_eq!(r, Err(CryptoError::Aead));
    }

    #[test]
    fn aead_rejects_aad_tampering() {
        let ss = [0x77u8; KEM_SHARED_LEN];
        let na = [0x11u8; NONCE_LEN];
        let ng = [0x22u8; NONCE_LEN];
        let keys = SessionKeys::derive(&ss, &na, &ng, 0xAABB, 0xCCDD);
        let (ct, tag) = aead_seal(
            &keys,
            Direction::GroundToAircraft,
            7,
            b"good-header",
            b"payload",
        )
        .expect("seal");
        let r = aead_open(
            &keys,
            Direction::GroundToAircraft,
            7,
            b"evil-header",
            &ct,
            &tag,
        );
        assert_eq!(r, Err(CryptoError::Aead));
    }

    #[test]
    fn derive_with_zero_qkd_matches_plain_derive() {
        let ss = [0x77u8; KEM_SHARED_LEN];
        let na = [0x11u8; NONCE_LEN];
        let ng = [0x22u8; NONCE_LEN];
        let plain = SessionKeys::derive(&ss, &na, &ng, 0xAABB, 0xCCDD);
        let zero = SessionKeys::derive_with_qkd(&ss, &na, &ng, 0xAABB, 0xCCDD, &[0u8; 32]);
        assert_eq!(*plain.k_ag, *zero.k_ag);
        assert_eq!(*plain.k_ga, *zero.k_ga);
        assert_eq!(*plain.iv_ag, *zero.iv_ag);
        assert_eq!(*plain.iv_ga, *zero.iv_ga);
    }

    #[test]
    fn nonzero_qkd_changes_keys() {
        let ss = [0x77u8; KEM_SHARED_LEN];
        let na = [0x11u8; NONCE_LEN];
        let ng = [0x22u8; NONCE_LEN];
        let plain = SessionKeys::derive(&ss, &na, &ng, 0xAABB, 0xCCDD);
        let with_qkd =
            SessionKeys::derive_with_qkd(&ss, &na, &ng, 0xAABB, 0xCCDD, &[0xFFu8; 32]);
        assert_ne!(*plain.k_ag, *with_qkd.k_ag);
        assert_ne!(*plain.k_ga, *with_qkd.k_ga);
    }

    #[test]
    fn directions_use_independent_keys() {
        let ss = [0x77u8; KEM_SHARED_LEN];
        let na = [0x11u8; NONCE_LEN];
        let ng = [0x22u8; NONCE_LEN];
        let keys = SessionKeys::derive(&ss, &na, &ng, 0xAABB, 0xCCDD);
        let (ct, tag) = aead_seal(
            &keys,
            Direction::AircraftToGround,
            1,
            b"aad",
            b"pt",
        )
        .expect("seal");
        // Decrypt under the wrong direction -> reject.
        let r = aead_open(
            &keys,
            Direction::GroundToAircraft,
            1,
            b"aad",
            &ct,
            &tag,
        );
        assert_eq!(r, Err(CryptoError::Aead));
    }
}
