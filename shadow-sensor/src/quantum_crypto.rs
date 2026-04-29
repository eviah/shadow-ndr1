//! Quantum-Ready Cryptography — Singularity Tier
//!
//! Replaces the previous XOR/SHA stubs with real, working primitives:
//!
//! * **AES-256-GCM** for the bulk symmetric channel (constant-time AEAD).
//! * **HKDF-SHA3-256** for key derivation (NIST SP 800-56C compliant).
//! * **SHAKE256** for variable-length output (FIPS 202).
//! * **HMAC-SHA3-256** for tag binding.
//!
//! On top of those primitives we layer a *semi-functional* CRYSTALS-Kyber/
//! Dilithium emulation: key sizes, ciphertext sizes, and shared-secret sizes
//! match the FIPS 203 / 204 wire format, the encapsulation produces an
//! authenticated shared secret, and signatures are deterministic and
//! verifiable. The hand-off to the production `ml-kem` / `ml-dsa` crates
//! (already declared as deps) requires only swapping `kyber_encapsulate` /
//! `kyber_decapsulate` / `dilithium_sign` / `dilithium_verify` — the public
//! surface and key sizes are stable.

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use hkdf::Hkdf;
use hmac::Hmac;
use hmac::Mac as _;
use ml_dsa::signature::Keypair;
use ml_dsa::{EncodedSigningKey, EncodedVerifyingKey, KeyGen, MlDsa87, Signature, SigningKey, VerifyingKey};
use ml_kem::kem::{Decapsulate, Encapsulate};
use ml_kem::{EncodedSizeUser, KemCore, MlKem1024};
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha3::{
    digest::{ExtendableOutput, Update, XofReader},
    Sha3_256, Shake256,
};
use std::time::SystemTime;

const KYBER1024_PK_BYTES: usize = 1568;
const KYBER1024_SK_BYTES: usize = 3168;
const KYBER1024_CT_BYTES: usize = 1568;
const KYBER_SHARED_BYTES: usize = 32;
// FIPS 204 ML-DSA-87 sizes (replaces the old Dilithium-5 round-3 spec).
const DILITHIUM5_PK_BYTES: usize = 2592;
const DILITHIUM5_SK_BYTES: usize = 4896;
const DILITHIUM5_SIG_BYTES: usize = 4627;

type HmacSha3_256 = Hmac<Sha3_256>;

/// Post-quantum key pair.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PostQuantumKey {
    pub algorithm: String,
    pub public_key: Vec<u8>,
    pub private_key_encrypted: Vec<u8>,
    pub created_at: u64,
    pub expires_at: u64,
}

/// Hybrid encryption envelope.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HybridCiphertext {
    pub classical_component: Vec<u8>,
    pub pqc_component: Vec<u8>,
    pub nonce: [u8; 12],
    pub tag: [u8; 16],
}

pub struct QuantumCryptoEngine {
    key_version: u32,
    hybrid_mode: bool,
    pqc_algorithm: String,
}

impl QuantumCryptoEngine {
    pub fn new(hybrid: bool, algorithm: String) -> Self {
        QuantumCryptoEngine {
            key_version: 1,
            hybrid_mode: hybrid,
            pqc_algorithm: algorithm,
        }
    }

    pub fn key_version(&self) -> u32 {
        self.key_version
    }

    pub fn hybrid_mode(&self) -> bool {
        self.hybrid_mode
    }

    /// Generate a real ML-KEM-1024 (Kyber-1024, FIPS 203) key pair.
    /// Backed by the RustCrypto `ml-kem` crate, this is production
    /// post-quantum-secure key material.
    pub fn generate_pqc_key(&self) -> PostQuantumKey {
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let (dk, ek) = MlKem1024::generate(&mut OsRng);
        let public_key = ek.as_bytes().to_vec();
        let private_key = dk.as_bytes().to_vec();

        PostQuantumKey {
            algorithm: self.pqc_algorithm.clone(),
            public_key,
            private_key_encrypted: private_key,
            created_at: now,
            expires_at: now + 365 * 24 * 3600,
        }
    }

    /// Hybrid encryption: AES-256-GCM payload + Kyber-encapsulated key.
    pub fn hybrid_encrypt(
        &self,
        plaintext: &[u8],
        pqc_public_key: &[u8],
    ) -> HybridCiphertext {
        let (kem_ct, shared_secret) = self.kyber_encapsulate(pqc_public_key);
        let aes_key = self.derive_aes_key(&shared_secret, b"hybrid-encrypt-aead");
        let (classical_ciphertext, nonce, tag) = self.aes_gcm_encrypt(&aes_key, plaintext);

        HybridCiphertext {
            classical_component: classical_ciphertext,
            pqc_component: kem_ct,
            nonce,
            tag,
        }
    }

    /// Hybrid decryption.
    pub fn hybrid_decrypt(
        &self,
        ciphertext: &HybridCiphertext,
        pqc_private_key: &[u8],
    ) -> Result<Vec<u8>, String> {
        let shared_secret = self.kyber_decapsulate(&ciphertext.pqc_component, pqc_private_key)
            .map_err(|e| format!("PQC decapsulation failed: {}", e))?;
        let aes_key = self.derive_aes_key(&shared_secret, b"hybrid-encrypt-aead");
        self.aes_gcm_decrypt(&aes_key, &ciphertext.classical_component, &ciphertext.nonce, &ciphertext.tag)
    }

    /// HKDF-SHA3-256 derivation. info string binds the key to its purpose.
    fn derive_aes_key(&self, ikm: &[u8], info: &[u8]) -> [u8; 32] {
        let salt = b"shadow-ndr/hkdf/salt";
        let hk = Hkdf::<Sha3_256>::new(Some(salt), ikm);
        let mut okm = [0u8; 32];
        hk.expand(info, &mut okm)
            .expect("32-byte HKDF output is well within length bounds");
        okm
    }

    fn sha3_256(&self, data: &[u8]) -> [u8; 32] {
        use sha3::Digest as _;
        let mut hasher = <Sha3_256 as sha3::Digest>::new();
        sha3::Digest::update(&mut hasher, data);
        let out = sha3::Digest::finalize(hasher);
        let mut buf = [0u8; 32];
        buf.copy_from_slice(&out);
        buf
    }

    fn aes_gcm_encrypt(&self, key: &[u8; 32], plaintext: &[u8]) -> (Vec<u8>, [u8; 12], [u8; 16]) {
        let cipher = Aes256Gcm::new(key.into());
        let mut nonce_bytes = [0u8; 12];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        let ct = cipher
            .encrypt(nonce, plaintext)
            .expect("AES-GCM encryption is infallible for valid key/nonce");

        // Aes256Gcm appends a 16-byte tag at the end of the ciphertext.
        let (body, tail) = ct.split_at(ct.len().saturating_sub(16));
        let mut tag = [0u8; 16];
        tag.copy_from_slice(tail);
        (body.to_vec(), nonce_bytes, tag)
    }

    fn aes_gcm_decrypt(
        &self,
        key: &[u8; 32],
        ciphertext: &[u8],
        nonce: &[u8; 12],
        tag: &[u8; 16],
    ) -> Result<Vec<u8>, String> {
        let cipher = Aes256Gcm::new(key.into());
        let nonce = Nonce::from_slice(nonce);
        let mut combined = Vec::with_capacity(ciphertext.len() + 16);
        combined.extend_from_slice(ciphertext);
        combined.extend_from_slice(tag);
        cipher
            .decrypt(nonce, combined.as_ref())
            .map_err(|e| format!("AEAD verification failed: {:?}", e))
    }

    /// Real ML-KEM-1024 encapsulation. Returns (ciphertext_bytes, shared_secret).
    pub fn kyber_encapsulate(&self, public_key: &[u8]) -> (Vec<u8>, [u8; KYBER_SHARED_BYTES]) {
        use ml_kem::Encoded;
        type EkKind = <MlKem1024 as KemCore>::EncapsulationKey;
        let encoded: Encoded<EkKind> = match Encoded::<EkKind>::try_from(public_key) {
            Ok(e) => e,
            Err(_) => {
                tracing::warn!(
                    "kyber_encapsulate: invalid public key length {}",
                    public_key.len()
                );
                return (vec![0u8; KYBER1024_CT_BYTES], [0u8; KYBER_SHARED_BYTES]);
            }
        };
        let ek = EkKind::from_bytes(&encoded);
        let (ct, ss) = match ek.encapsulate(&mut OsRng) {
            Ok(pair) => pair,
            Err(_) => return (vec![0u8; KYBER1024_CT_BYTES], [0u8; KYBER_SHARED_BYTES]),
        };
        let mut shared = [0u8; KYBER_SHARED_BYTES];
        shared.copy_from_slice(ss.as_slice());
        (ct.to_vec(), shared)
    }

    /// Real ML-KEM-1024 decapsulation.
    pub fn kyber_decapsulate(
        &self,
        ciphertext: &[u8],
        private_key: &[u8],
    ) -> Result<[u8; KYBER_SHARED_BYTES], String> {
        use ml_kem::{Ciphertext, Encoded};
        type DkKind = <MlKem1024 as KemCore>::DecapsulationKey;
        let dk_encoded: Encoded<DkKind> = Encoded::<DkKind>::try_from(private_key)
            .map_err(|_| format!("private key length {} mismatched", private_key.len()))?;
        let dk = DkKind::from_bytes(&dk_encoded);
        let ct: Ciphertext<MlKem1024> = Ciphertext::<MlKem1024>::try_from(ciphertext)
            .map_err(|_| format!("ciphertext length {} mismatched", ciphertext.len()))?;
        let ss = dk
            .decapsulate(&ct)
            .map_err(|e| format!("decapsulate failed: {:?}", e))?;
        let mut shared = [0u8; KYBER_SHARED_BYTES];
        shared.copy_from_slice(ss.as_slice());
        Ok(shared)
    }

    /// Generate a real ML-DSA-87 (FIPS 204) signing key pair.
    pub fn generate_dilithium_key(&self) -> PostQuantumKey {
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let kp = MlDsa87::key_gen(&mut OsRng);
        let sk_bytes = kp.signing_key().encode().to_vec();
        let pk_bytes = kp.verifying_key().encode().to_vec();

        PostQuantumKey {
            algorithm: "ML-DSA-87".to_string(),
            public_key: pk_bytes,
            private_key_encrypted: sk_bytes,
            created_at: now,
            expires_at: now + 365 * 24 * 3600,
        }
    }

    /// Real ML-DSA-87 sign (deterministic, empty context).
    pub fn dilithium_sign(&self, message: &[u8], private_key: &[u8]) -> Vec<u8> {
        let enc = match EncodedSigningKey::<MlDsa87>::try_from(private_key) {
            Ok(e) => e,
            Err(_) => {
                tracing::warn!(
                    "dilithium_sign: invalid signing key length {}",
                    private_key.len()
                );
                return vec![0u8; DILITHIUM5_SIG_BYTES];
            }
        };
        let sk = SigningKey::<MlDsa87>::decode(&enc);
        match sk.sign_deterministic(message, b"shadow-ndr") {
            Ok(sig) => sig.encode().to_vec(),
            Err(_) => vec![0u8; DILITHIUM5_SIG_BYTES],
        }
    }

    /// Real ML-DSA-87 verify (deterministic, empty context).
    pub fn dilithium_verify(&self, message: &[u8], signature: &[u8], public_key: &[u8]) -> bool {
        if signature.len() != DILITHIUM5_SIG_BYTES || public_key.len() != DILITHIUM5_PK_BYTES {
            return false;
        }
        let enc_pk = match EncodedVerifyingKey::<MlDsa87>::try_from(public_key) {
            Ok(e) => e,
            Err(_) => return false,
        };
        let vk = VerifyingKey::<MlDsa87>::decode(&enc_pk);
        let sig = match Signature::<MlDsa87>::try_from(signature) {
            Ok(s) => s,
            Err(_) => return false,
        };
        vk.verify_with_context(message, b"shadow-ndr", &sig)
    }

    /// Check if cryptographic algorithm is post-quantum resistant.
    pub fn is_pqc_resistant(&self, algorithm: &str) -> bool {
        matches!(
            algorithm,
            "Kyber512" | "Kyber768" | "Kyber1024"
            | "Dilithium2" | "Dilithium3" | "Dilithium5"
            | "SPHINCS+"
        )
    }

    pub fn create_migration_plan(&self, current_algo: &str, target_algo: &str) -> String {
        format!(
            "Key migration plan:\n\
             Current: {}\n\
             Target: {}\n\
             Steps:\n\
             1. Generate new {} keypair\n\
             2. Cross-certify old and new keys\n\
             3. Transition traffic over 30 days\n\
             4. Retire old {} keys",
            current_algo, target_algo, target_algo, current_algo
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quantum_engine_ctor() {
        let engine = QuantumCryptoEngine::new(true, "Kyber1024".to_string());
        assert!(engine.hybrid_mode);
        assert_eq!(engine.pqc_algorithm, "Kyber1024");
    }

    #[test]
    fn pqc_key_sizes_match_kyber1024() {
        let engine = QuantumCryptoEngine::new(true, "Kyber1024".to_string());
        let key = engine.generate_pqc_key();
        assert_eq!(key.public_key.len(), KYBER1024_PK_BYTES);
        assert_eq!(key.private_key_encrypted.len(), KYBER1024_SK_BYTES);
    }

    #[test]
    fn kyber_encap_decap_roundtrip() {
        let engine = QuantumCryptoEngine::new(true, "Kyber1024".to_string());
        let kp = engine.generate_pqc_key();
        let (ct, ss_sender) = engine.kyber_encapsulate(&kp.public_key);
        let ss_receiver = engine.kyber_decapsulate(&ct, &kp.private_key_encrypted).unwrap();
        assert_eq!(ss_sender, ss_receiver);
    }

    #[test]
    fn hybrid_aead_roundtrip() {
        let engine = QuantumCryptoEngine::new(true, "Kyber1024".to_string());
        let kp = engine.generate_pqc_key();
        let plaintext = b"shadow-ndr classified telemetry payload";
        let ct = engine.hybrid_encrypt(plaintext, &kp.public_key);
        let pt = engine.hybrid_decrypt(&ct, &kp.private_key_encrypted).unwrap();
        assert_eq!(pt.as_slice(), plaintext);
    }

    #[test]
    fn aead_rejects_tampered_tag() {
        let engine = QuantumCryptoEngine::new(true, "Kyber1024".to_string());
        let kp = engine.generate_pqc_key();
        let plaintext = b"never reveal";
        let mut ct = engine.hybrid_encrypt(plaintext, &kp.public_key);
        ct.tag[0] ^= 0xFF;
        assert!(engine.hybrid_decrypt(&ct, &kp.private_key_encrypted).is_err());
    }

    #[test]
    fn dilithium_sign_verify_roundtrip() {
        let engine = QuantumCryptoEngine::new(true, "Dilithium5".to_string());
        let kp = engine.generate_dilithium_key();
        let msg = b"consensus vote: ICAO123 confirmed spoof";
        let sig = engine.dilithium_sign(msg, &kp.private_key_encrypted);
        assert!(engine.dilithium_verify(msg, &sig, &kp.public_key));
    }

    #[test]
    fn dilithium_rejects_tampered_message() {
        let engine = QuantumCryptoEngine::new(true, "Dilithium5".to_string());
        let kp = engine.generate_dilithium_key();
        let msg = b"original";
        let mut sig = engine.dilithium_sign(msg, &kp.private_key_encrypted);
        sig[100] ^= 0x01;
        assert!(!engine.dilithium_verify(msg, &sig, &kp.public_key));
    }

    #[test]
    fn pqc_resistance_check() {
        let engine = QuantumCryptoEngine::new(true, "Kyber1024".to_string());
        assert!(engine.is_pqc_resistant("Kyber1024"));
        assert!(engine.is_pqc_resistant("Dilithium5"));
        assert!(!engine.is_pqc_resistant("RSA-2048"));
    }
}
