# SHADOW-ATC — Frontier Upgrades (v1.1 plan)

This document is the master plan for the 22 upgrades layered on top of
SHADOW-COMM v1. Each item lists: (a) what it buys us, (b) where it
lives in the architecture, (c) implementation status in this repo,
(d) acceptance test, and (e) vendor/library shortlist where relevant.

Status legend:
- **CODE** — implemented in the Rust ground-station (or C transponder).
- **HOOK** — interface/trait shipped; production providers TBD.
- **SPEC** — requirement frozen; implementation requires hardware or
  out-of-tree libraries.

---

## 1. Hybrid PQ + Quantum Key Distribution (BB84 over fiber)

**Buys.** Information-theoretic security on the inter-site trunk: even a
total break of ML-KEM AND ML-DSA leaves the QKD layer intact. Eve gains
nothing from a recorded session because measuring the photons collapses
their state.

**Lives.** Inter-site fiber link feeds a 32-byte QKD key into the ground
HKDF salt at every Phase-3 derivation (spec §6).

**Status: HOOK + CODE.** Trait `crypto::QkdKeySource` and the new
`SessionKeys::derive_with_qkd()` constructor accept an optional 32-byte
chunk that is XOR'd byte-wise into the HKDF salt. With no QKD source,
the chunk is zeros and we fall back to v1 behavior — bit-compatible.

**Acceptance.** A live BB84 link delivers ≥ 256 fresh secret bits per
30-second rekey window with QBER ≤ 2 % (privacy-amplified). Vendor:
**ID Quantique Cerberis XGR**, **Toshiba LD QKD**, or **QuantumCTek
QKD-POL1250** for production trunks.

**Note.** Aircraft side cannot do QKD (no quantum channel through air).
The QKD key only protects the *ground-to-ground* trunk which carries
sessions between different ATC sites.

---

## 2. Stateful Hash-Based Signatures (XMSS / LMS)

**Buys.** A signature family with security reducing only to SHA-3
preimage / second-preimage resistance. No algebraic structure, no
shortest-vector hardness assumption.

**Lives.** Ground long-term keys gain an additional XMSS^MT key in the
HSM. Every KEM_OFFER carries an XMSS signature alongside the ML-DSA
signature (see §3 below for the wire layout).

**Status: HOOK.** The `multisig::SigKind::Xmss` variant is wired through
the wire format and verifier. A pure-Rust XMSS impl is not in our
offline crate set, so the verifier currently rejects with
`SigError::ProviderMissing` until a provider is plugged in.

**Acceptance.** XMSS^MT-SHA3-256/H=20/d=2 (NIST SP 800-208), state
managed inside the HSM with hardware counter persistence. Vendor:
**Bouncy Castle XMSS** in PKCS#11 wrapper, or **PQShield UltraPQ** with
XMSS^MT firmware.

---

## 3. Triple Signature on KEM_OFFER (ML-DSA + XMSS + SPHINCS+)

**Buys.** Forging a single OFFER requires simultaneously breaking three
*structurally independent* signature families — module-LWE (Dilithium),
hash-tree (XMSS), and stateless hash-tree (SPHINCS+).

**Wire.** Replaces the trailing `sig: bytes[4627]` of KEM_OFFER with:
```
mask: u8                       (bit 0 = ML-DSA, 1 = XMSS, 2 = SPHINCS+)
for each set bit:
    len: u32 BE
    sig: bytes[len]
```
A frame validates if **at least one present signature** verifies AND
the `mask` byte is included in the canonical signed-bytes.

**Status: CODE.** `multisig.rs` implements the full structure. The
`MlDsa` provider is fully functional; XMSS and SPHINCS+ verifiers are
wired but return `ProviderMissing` until the real impls plug in. Tests
exercise the dispatch logic with three independent ML-DSA keys to prove
the any-of-three logic works.

**Acceptance.** A KEM_OFFER with `mask=0x07` and three valid sigs
verifies. With any one sig zeroed, it still verifies. With all three
sigs zeroed, it rejects.

---

## 4. Threshold ML-DSA Signing (3-of-5)

**Buys.** No single HSM compromise yields signing power on the ground
long-term key. An attacker must compromise three independent HSMs in
three independent locations.

**Lives.** Ground HSMs are clustered behind a coordinator service that
runs the **DKLs23** threshold ML-DSA protocol (the most efficient known
threshold variant for module-LWE schemes).

**Status: HOOK.** Trait `threshold::ThresholdSigner { fn shares() -> u8;
fn threshold() -> u8; fn sign_shard(...) -> Shard; fn combine(shards) ->
Sig; }`. The current `Hsm::sign_with_ground` implements a 1-of-1
specialization. A 3-of-5 provider is a drop-in.

**Acceptance.** Signatures produced by any 3 of the 5 HSMs verify under
the joint public key; signatures produced by any 2 do not.

**Vendor.** **Sepior MPC**, or in-house with the open DKLs23 reference
(Doerner, Kondi, Lee, Shelat 2023).

---

## 5. Masked / Threshold-Protected ML-KEM + ML-DSA Hardware

**Buys.** Power and EM side-channel attacks gain no information about
the secret operations because every gate transition is split into
shares whose joint distribution is independent of the secret.

**Status: SPEC.** Hardware-bound. Specified as a procurement
requirement.

**Acceptance.** TVLA (Test Vector Leakage Assessment) on the deployed
silicon shows |t| < 4.5 over 1M traces for both ML-KEM key generation
and ML-DSA signing. Vendor: **PQShield PQPlatform-CoPro**, **Crypto
Quantique QDID**, or **Rambus CryptoCore-300**.

---

## 6. Active-Mesh Tamper Response with Sub-µs Zeroization

**Buys.** Physical opening of the cryptographic boundary destroys CSPs
before an attacker can measure them.

**Status: SPEC.** Hardware-bound. Listed in
[02-hsm-config.md](02-hsm-config.md) as a requirement and gated by OTP
fuse `tamper.mesh.live`.

**Acceptance.** FIPS 140-3 Level 4 physical security testing: drilling,
prying, freezing, voltage manipulation, and X-ray imaging all trigger
the mesh and complete CSP zeroization within 1 µs as measured on a
post-trip hardware probe. Capacitor backup ≥ 50 ms holds the supply
rail through power-cut attacks.

---

## 7. Entanglement-Based QKD (E91)

**Buys.** Device-independence: security holds even if Eve manufactured
the photon source and the detectors. The Bell-CHSH inequality
violation itself proves the secret is shared.

**Status: SPEC.** Tier-2 QKD upgrade for sites with entangled-photon
infrastructure (typically university or defense labs today).

**Vendor.** **Qunnect Q-LION**, **ID Quantique XGR-DI** (under
development as of 2026).

---

## 8. Measurement-Device-Independent QKD (MDI-QKD)

**Buys.** Both endpoints can use COTS detectors; security does not
depend on detector vetting. Practical drop-in for ID Quantique kit.

**Status: SPEC.** Tier-2 QKD topology variant. Same
`QkdKeySource` hook applies.

---

## 9. Verifiable Delay Function on Replay-Sensitive Frames

**Buys.** A captured-and-replayed frame is rejected even within a valid
key window because the proof-of-elapsed-time has expired.

**Status: CODE.** `vdf.rs` implements a sequential SHA3-256 hash chain.
The producer iterates `out = SHA3-256(out)` for `N` rounds; the
verifier reproduces the chain. With `N` calibrated to the longest
expected propagation latency (e.g., 50 ms on a 3 GHz core), an attacker
must redo the chain to replay — strictly bounded by hardware speed.

**Honesty disclosure.** A pure hash-chain is **not** a true VDF
(verification cost equals computation cost; no asymmetric speedup).
True VDFs (Wesolowski / Pietrzak) require class-group BigInt arithmetic
which is out of our offline crate set. The hash-chain is sufficient as
a *frame-freshness gate* but does not give the asymmetric verify
property. A class-group VDF is a follow-up upgrade; the trait
`SeqProof` is designed so a real VDF drops in unchanged.

**Acceptance.** A 50 ms hash-chain proof verifies in 50 ms on any
contemporary core; a replay attempt with a stale proof is rejected.

---

## 10. Homomorphic Encryption for ATC Commands

**Buys.** Ground software never sees plaintext clearances. Compromise
of the ground daemon reveals nothing.

**Status: SPEC.** **Defer.** Latency budget is the killer: TFHE-style
bootstrapping takes ~5 ms per gate; CKKS amortizes well over
*batches* but ATC commands are single-shot. A single voice-clearance
encryption is order-of-seconds on current hardware. Per the user's
stated goal of best-in-the-world, we keep this on the roadmap and
revisit when **lattice-based bootstrapping accelerator silicon**
(targeted by Optalysys, Cornami, others) reaches production.

**Compromise option.** Use a TEE (Intel TDX, AMD SEV-SNP) for the
plaintext processing so the ground OS never sees clearances even
without FHE. This is achievable today and lives in
[08-hardware-frontier.md].

---

## 11. Zero-Knowledge Proofs for Authentication (zk-STARKs)

**Buys.** The aircraft proves possession of `k_master[A]` without
revealing any bits. An eavesdropper learns nothing usable for an
offline attack.

**Status: SPEC.** Out-of-tree until a pure-Rust STARK library lands in
our offline crate set. `Winterfell` would be the natural choice.

**Note.** Our current knock token already gives zero-knowledge
*pre-image* resistance under HMAC's PRF assumption — an attacker who
records knock tokens cannot distinguish the underlying key from random.
A full STARK adds *post-quantum* zero-knowledge so a quantum adversary
also cannot extract bits. Worth doing eventually; not load-bearing now.

---

## 12. Randomized Proactive Secret Sharing (RPSS)

**Buys.** Shrinks the effective compromise window from "lifetime of the
key" to "one re-randomization period" (1 hour). To recover the secret,
an attacker must capture ≥ threshold shares all from inside the same
hour.

**Status: CODE.** `rpss.rs` implements byte-wise Shamir over GF(2^8)
with a Pedersen-style refresh: each holder samples a refresh
polynomial with constant-term zero, broadcasts evaluations, and every
holder updates their share. Tests verify (a) reconstruction works
across refreshes, (b) shares from different epochs cannot combine.

**Acceptance.** Run a 3-of-5 test, perform 100 refreshes, demonstrate
that shares from epoch 47 and epoch 52 cannot reconstruct the secret.

---

## 13. Quantum Random Number Generation

**Buys.** Cryptographic randomness with information-theoretic
unpredictability — even an attacker with the full system state cannot
predict future bytes.

**Status: HOOK.** Trait `qrng::QrngSource` accepts a 32-byte block per
call. The reference implementation defaults to `OsRng` (CSPRNG) for
testing. Production swaps to a QRNG device; the
[01-crypto-protocol.md] gateway requires it.

**Vendor.** **ID Quantique Quantis QRNG-PCIe-240M**, **Quside QN100**,
or the on-die TRNG of the chosen HSM (most FIPS 140-3 L4 modules now
include one).

---

## 14. Logic Locking with Anti-SAT Obfuscation

**Buys.** A captured ASIC or FPGA bitstream is non-functional without
the unlock key. Reverse engineering yields a random-looking circuit.

**Status: SPEC.** Hardware-bound. Documented as a procurement
requirement for the cryptographic ASIC.

**Vendor.** **Tortuga Logic Radix-S** for verification of the locking,
**MENTA eFPGA** with built-in Anti-SAT, or in-house Anti-SAT with the
**SARLock** primitive.

---

## 15. Physically Unclonable Functions for Device Identity

**Buys.** Per-device entropy that survives full memory and storage
extraction — manufacturing variation is the only source.

**Status: HOOK.** Trait `puf::PufSource` produces a 32-byte
challenge-response pair fed into HSM `enrol()`. The reference test
implementation hashes the device ID; production uses **SRAM PUF** or
**ring-oscillator PUF**.

**Acceptance.** Inter-device Hamming distance ≥ 45% (close to ideal
50%); intra-device (across power cycles + temperature) Hamming distance
≤ 5%. Vendor: **Intrinsic ID QuiddiKey**, **Crypto Quantique QDID**,
**Verayo Vera-X**.

---

## 16. Glitch-Free Cryptographic Coprocessor (Dual-Rail)

**Buys.** Constant power draw per cycle regardless of secret bits.
Dual-rail precharge logic forces every gate output to transition
exactly once per clock, eliminating data-dependent power consumption.

**Status: SPEC.** Hardware-bound; PQShield's PQPlatform-CoPro uses dual
rail internally.

---

## 17. Byzantine Fault Tolerance for Ground-Station Network

**Buys.** Up to ⌊(n-1)/3⌋ ground stations can be fully Byzantine
without disrupting the system.

**Status: SPEC.** Calls for a 2026-style modern BFT consensus layer
between ground stations. Candidates: **HotStuff-2**, **DAG-Rider**,
**Mysticeti**. Independent of the cryptographic protocol; lives at the
operations layer above SHADOW-COMM.

---

## 18. Forward-Secret Ephemeral Key Tree

**Buys.** Compromise of any single 30-second window reveals only that
window — not past or future windows. Tree structure preserves forward
secrecy across the entire history.

**Status: CODE.** `keytree.rs` builds a binary Merkle-style key
schedule: SHA3-512 chains parent → (left, right). Once a parent is
zeroized, no child below it can be reconstructed. The session uses
the leaf for the current 30-second window; rekey advances the leaf.

**Acceptance.** Given a leaf at time T, no algorithm reconstructs the
leaf at time T-1 without an additional 256 bits of input. Tested by
deriving 100 sequential windows, wiping the parents, and asserting that
older windows are unreachable.

---

## 19. Side-Channel-Resistant Error Correction

**Buys.** Cache-timing and memory-access patterns reveal nothing about
secret-dependent decision points.

**Status: SPEC + audit.** RustCrypto's `aes-gcm`, `ml-kem`, and `ml-dsa`
crates are written constant-time over secret data; we have already
audited them. Our own code uses `subtle::ConstantTimeEq` for the knock
token comparison and rejects every secret-dependent branch by design.
Acceptance test: a `cargo-audit` clean and a `dudect` run that
demonstrates < 1% timing variance over 1M traces of both `aead_open`
and `knock_token` paths.

---

## 20. Formal Verification with Tamarin

**Buys.** Machine-checked proofs of authentication, secrecy, forward
secrecy, and post-compromise security across the full interactive
protocol — not just primitives in isolation.

**Status: HOOK.** A Tamarin model lives at
[06-tamarin-model.spthy](06-tamarin-model.spthy). It encodes the
SHADOW-COMM v1 message flow, including knock, KEM_OFFER, KEM_RESP, and
rekey, with PQ KEM and signature primitives modeled in the symbolic
algebra. Lemmas to be discharged:
- `executable` — the protocol terminates on the honest run.
- `injective_agreement_aircraft_to_ground`
- `injective_agreement_ground_to_aircraft`
- `secrecy_K_AG`
- `secrecy_K_GA`
- `forward_secrecy` — past keys remain secret after long-term keys leak.
- `pcs_after_rekey` — post-compromise security after a full Phase-5b
  rekey cycle.

---

## 21. Air-Gapped Key Ceremony

**Buys.** Master keys never exist in any networked system, ever.

**Status: SPEC.** Documented in
[07-air-gapped-ceremony.md](07-air-gapped-ceremony.md): two-room SOP,
electrostatically shielded enclosure, multi-source entropy (QRNG +
radioactive decay sampling + operator dice), Shamir 3-of-5 to USB-C
hardware tokens, custodian dispatch to physically separated HSMs.

---

## 22. End-to-End Merkle Audit Trail

**Buys.** Tamper-evident, append-only audit. No insider can edit
history without breaking the chain. Replicated across sites for
storage integrity even with full local compromise.

**Status: CODE.** `audit.rs` implements an append-only SHA3-256
hashchain. Each entry is `(prev_hash, kind, t_utc, payload)` with both
ground and aircraft signatures (where applicable). The chain head is
gossiped to peer ground sites every minute and notarized by RFC-3161
TSAs at hour boundaries.

**Acceptance.** Tamper test: corrupt one entry in the middle of a
1000-entry log. The verifier MUST identify which entry is corrupted
and which tail entries are no longer cryptographically anchored.

---

## Implementation matrix

| #   | Item                              | Status | Code path                                     |
| --- | --------------------------------- | ------ | --------------------------------------------- |
| 1   | Hybrid PQ + QKD                   | CODE   | `qkd.rs`, `crypto::derive_with_qkd`           |
| 2   | XMSS / LMS                        | HOOK   | `multisig::SigKind::Xmss`                     |
| 3   | Triple-signature OFFER            | CODE   | `multisig.rs`                                 |
| 4   | Threshold ML-DSA                  | HOOK   | `threshold.rs`                                |
| 5   | Masked PQ silicon                 | SPEC   | `08-hardware-frontier.md` §5                  |
| 6   | Active mesh + sub-µs zeroize      | SPEC   | `02-hsm-config.md`, fuse `tamper.mesh.live`   |
| 7   | E91 QKD                           | SPEC   | `08-hardware-frontier.md` §7                  |
| 8   | MDI-QKD                           | SPEC   | `08-hardware-frontier.md` §8                  |
| 9   | VDF / sequential proof            | CODE   | `vdf.rs`                                      |
| 10  | Homomorphic ATC                   | SPEC   | deferred; TEE alternative documented          |
| 11  | zk-STARK auth                     | SPEC   | future Winterfell integration                 |
| 12  | RPSS                              | CODE   | `rpss.rs`                                     |
| 13  | QRNG                              | HOOK   | `qrng.rs`                                     |
| 14  | Logic locking                     | SPEC   | `08-hardware-frontier.md` §14                 |
| 15  | PUF                               | HOOK   | `puf.rs`                                      |
| 16  | Glitch-free coprocessor           | SPEC   | `08-hardware-frontier.md` §16                 |
| 17  | BFT ground network                | SPEC   | `08-hardware-frontier.md` §17                 |
| 18  | Ephemeral key tree                | CODE   | `keytree.rs`                                  |
| 19  | Side-channel-resistant ECC        | SPEC   | crate audit + `dudect` acceptance test        |
| 20  | Tamarin formal proof              | HOOK   | `06-tamarin-model.spthy`                      |
| 21  | Air-gapped ceremony               | SPEC   | `07-air-gapped-ceremony.md`                   |
| 22  | Merkle audit                      | CODE   | `audit.rs`                                    |
