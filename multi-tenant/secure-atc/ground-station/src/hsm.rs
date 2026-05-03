//! HSM interface — the only path through which long-term keys are touched.
//!
//! In production this is a PKCS#11 binding to a FIPS 140-3 Level 4 device.
//! Here it is a software emulator so the protocol logic can be exercised
//! end-to-end without real hardware. The shape — opaque handles, no key
//! exfil paths — matches the production interface so swapping the
//! emulator for a real binding is a build-flag change.
//!
//! See [`02-hsm-config.md`](../../docs/02-hsm-config.md) for the policy
//! the HSM enforces.

use std::collections::HashMap;

use kem::{Decapsulate, Encapsulate};
use ml_dsa::{
    EncodedSignature, KeyGen, KeyPair, MlDsa87, Signature, VerifyingKey,
    signature::{Signer, Verifier},
};
use ml_kem::{Ciphertext, Encoded, EncodedSizeUser, KemCore, MlKem1024};
use rand::rngs::OsRng;
use sha3::{Digest, Sha3_256};
use zeroize::Zeroizing;

use crate::protocol::KEM_SHARED_LEN;

/// Convenience aliases for ml-dsa's parameterized types under MlDsa87.
type Vk87 = VerifyingKey<MlDsa87>;
type Sig87 = Signature<MlDsa87>;
type Kp87 = KeyPair<MlDsa87>;

/// Errors surfaced by the HSM. Variants are deliberately coarse — the
/// operational plane never returns specific cryptographic errors to
/// peers (spec §10).
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum HsmError {
    /// Aircraft id not in the enrolment set, or no public key on file.
    NotEnrolled,
    /// Signature verification failed.
    BadSignature,
    /// Kyber decapsulation failed (FO transform implicit reject).
    KemFailure,
    /// HSM is currently sealed (e.g. post-tamper).
    Sealed,
}

/// Per-aircraft enrolment record. `pk_a` is public; `k_master` never
/// leaves the HSM in plaintext in production.
struct Enrolment {
    pk_a: Vk87,
    k_master: Zeroizing<[u8; 32]>,
}

/// The simulated HSM. In production the corresponding state lives
/// inside the secure element; the application sees only handles.
pub struct Hsm {
    sealed: bool,
    /// Ground long-term Dilithium-5 keypair (`gs/longterm/sig`).
    keypair: Kp87,
    enrolments: HashMap<u64, Enrolment>,
}

impl Hsm {
    /// Boot the HSM: generate a long-term keypair and an empty
    /// enrolment table. In real hardware, the keypair is generated
    /// in factory and persists in the secure element.
    pub fn boot() -> Self {
        let keypair = MlDsa87::key_gen(&mut OsRng);
        Self {
            sealed: false,
            keypair,
            enrolments: HashMap::new(),
        }
    }

    /// Enrol an aircraft. Two operators are required in production
    /// (architecture §5); the emulator does not gate on this.
    pub fn enrol(&mut self, id_a: u64, pk_a: Vk87, k_master: [u8; 32]) {
        self.enrolments.insert(
            id_a,
            Enrolment {
                pk_a,
                k_master: Zeroizing::new(k_master),
            },
        );
    }

    /// Public-key fetch — used by the daemon during Phase 3 verification.
    pub fn aircraft_pk(&self, id_a: u64) -> Option<&Vk87> {
        self.enrolments.get(&id_a).map(|e| &e.pk_a)
    }

    /// Ground long-term public key — pinned by the aircraft at provisioning.
    pub fn ground_pk(&self) -> &Vk87 {
        self.keypair.verifying_key()
    }

    /// Read out the per-aircraft knock-derivation key.
    ///
    /// In production this call is replaced by an HSM-internal HMAC: the
    /// caller passes `bucket` and gets back the token, never the key.
    /// Here we expose the bytes only because the emulator runs the HMAC
    /// outside the secure element.
    pub fn knock_key(&self, id_a: u64) -> Option<[u8; 32]> {
        self.enrolments.get(&id_a).map(|e| *e.k_master)
    }

    /// Sign a payload with the ground long-term key.
    ///
    /// Used during Phase 2 KEM_OFFER (spec §4) and Phase 6 CLOSE.
    pub fn sign_with_ground(&self, payload: &[u8]) -> Result<Vec<u8>, HsmError> {
        if self.sealed {
            return Err(HsmError::Sealed);
        }
        let sig: Sig87 = self.keypair.signing_key().sign(payload);
        Ok(sig.encode().to_vec())
    }

    /// Verify a signature claimed to be from the given aircraft.
    pub fn verify_aircraft(
        &self,
        id_a: u64,
        payload: &[u8],
        sig_bytes: &[u8],
    ) -> Result<(), HsmError> {
        let pk = &self
            .enrolments
            .get(&id_a)
            .ok_or(HsmError::NotEnrolled)?
            .pk_a;
        let encoded: EncodedSignature<MlDsa87> = sig_bytes
            .try_into()
            .map_err(|_| HsmError::BadSignature)?;
        let sig = Sig87::decode(&encoded).ok_or(HsmError::BadSignature)?;
        pk.verify(payload, &sig).map_err(|_| HsmError::BadSignature)
    }

    /// On tamper or DR-1, seal the HSM. Cleared CSPs are not represented
    /// in the emulator (the keys are simply unreachable thereafter).
    pub fn seal(&mut self) {
        self.sealed = true;
    }
}

/// Produce a fresh ML-KEM-1024 ephemeral keypair for the ground side of
/// the handshake (spec §4).
///
/// The decapsulation key is held by the caller for the duration of the
/// handshake and zeroized immediately after Phase 3 (`esk` deletion in
/// spec §5 step 5).
pub fn ground_kem_keygen() -> (
    <MlKem1024 as KemCore>::DecapsulationKey,
    <MlKem1024 as KemCore>::EncapsulationKey,
) {
    MlKem1024::generate(&mut OsRng)
}

/// Aircraft side: encapsulate against the ground's encapsulation key.
///
/// Returns `(ct_bytes, ss)` where `ct_bytes` is what goes on the wire
/// and `ss` is the 32-byte KEM shared secret.
pub fn aircraft_kem_encap(
    ground_pk: &<MlKem1024 as KemCore>::EncapsulationKey,
) -> Result<(Vec<u8>, [u8; KEM_SHARED_LEN]), HsmError> {
    let (ct, ss) = ground_pk
        .encapsulate(&mut OsRng)
        .map_err(|_| HsmError::KemFailure)?;
    let mut out_ss = [0u8; KEM_SHARED_LEN];
    out_ss.copy_from_slice(&ss);
    Ok((ct.to_vec(), out_ss))
}

/// Ground side: decapsulate a Phase-3 ciphertext. `ml-kem` is constant
/// time over secret data — spec §12.
pub fn ground_kem_decap(
    esk: &<MlKem1024 as KemCore>::DecapsulationKey,
    ct_bytes: &[u8],
) -> Result<[u8; KEM_SHARED_LEN], HsmError> {
    let ct: Ciphertext<MlKem1024> = ct_bytes
        .try_into()
        .map_err(|_| HsmError::KemFailure)?;
    let ss = esk.decapsulate(&ct).map_err(|_| HsmError::KemFailure)?;
    let mut out = [0u8; KEM_SHARED_LEN];
    out.copy_from_slice(&ss);
    Ok(out)
}

/// Encode an ML-KEM-1024 encapsulation key for transmission.
pub fn encap_key_to_bytes(ek: &<MlKem1024 as KemCore>::EncapsulationKey) -> Vec<u8> {
    ek.as_bytes().to_vec()
}

/// Decode an ML-KEM-1024 encapsulation key from wire bytes.
pub fn encap_key_from_bytes(
    bytes: &[u8],
) -> Result<<MlKem1024 as KemCore>::EncapsulationKey, HsmError> {
    let arr: Encoded<<MlKem1024 as KemCore>::EncapsulationKey> = bytes
        .try_into()
        .map_err(|_| HsmError::KemFailure)?;
    Ok(<<MlKem1024 as KemCore>::EncapsulationKey>::from_bytes(&arr))
}

/// Compute the boot measurement that the silent monitoring plane
/// expects (spec §1 of HSM config). In production this is read from
/// the secure boot measurement registers; the emulator hashes the
/// active enrolment set and the ground public key as a stand-in.
pub fn boot_measurement(hsm: &Hsm) -> [u8; 32] {
    let mut h = Sha3_256::new();
    h.update(b"SHADOW-ATC/boot-measurement/v1");
    h.update(hsm.ground_pk().encode().as_slice());
    let mut ids: Vec<u64> = hsm.enrolments.keys().copied().collect();
    ids.sort_unstable();
    for id in ids {
        h.update(id.to_be_bytes());
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&h.finalize());
    out
}

/// Generate an aircraft long-term Dilithium-5 keypair. Used by tests
/// and the enrolment ceremony. Returns the keypair so the caller can
/// hand `pk_a` to the ground HSM.
pub fn aircraft_keygen() -> Kp87 {
    MlDsa87::key_gen(&mut OsRng)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ground_signs_aircraft_verifies_via_hsm() {
        let mut hsm = Hsm::boot();
        let aircraft = aircraft_keygen();
        hsm.enrol(0xAAA, aircraft.verifying_key().clone(), [0xCCu8; 32]);

        let payload = b"hello";
        let sig: Sig87 = aircraft.signing_key().sign(payload);
        let sig_bytes = sig.encode().to_vec();
        hsm.verify_aircraft(0xAAA, payload, &sig_bytes).expect("verify");
    }

    #[test]
    fn unenrolled_id_returns_not_enrolled() {
        let hsm = Hsm::boot();
        let r = hsm.verify_aircraft(0x999, b"x", &[0u8; 4627]);
        assert_eq!(r, Err(HsmError::NotEnrolled));
    }

    #[test]
    fn bad_signature_rejected() {
        let mut hsm = Hsm::boot();
        let aircraft = aircraft_keygen();
        hsm.enrol(0xAAA, aircraft.verifying_key().clone(), [0xCCu8; 32]);
        // Junk bytes of the right length.
        let r = hsm.verify_aircraft(0xAAA, b"x", &vec![0u8; 4627]);
        assert_eq!(r, Err(HsmError::BadSignature));
    }

    #[test]
    fn kem_round_trip() {
        let (esk, epk) = ground_kem_keygen();
        let (ct, ss_air) = aircraft_kem_encap(&epk).expect("encap");
        let ss_gnd = ground_kem_decap(&esk, &ct).expect("decap");
        assert_eq!(ss_air, ss_gnd);
    }

    #[test]
    fn encap_key_round_trip_bytes() {
        let (_esk, epk) = ground_kem_keygen();
        let bytes = encap_key_to_bytes(&epk);
        let decoded = encap_key_from_bytes(&bytes).expect("decode");
        let bytes2 = encap_key_to_bytes(&decoded);
        assert_eq!(bytes, bytes2);
    }

    #[test]
    fn ground_sign_payload_verifies_with_pinned_pk() {
        let hsm = Hsm::boot();
        let payload = b"phase-2 offer";
        let sig_bytes = hsm.sign_with_ground(payload).expect("sign");
        let encoded: EncodedSignature<MlDsa87> = sig_bytes.as_slice().try_into().expect("len");
        let sig = Sig87::decode(&encoded).expect("decode");
        hsm.ground_pk().verify(payload, &sig).expect("verify");
    }
}
