# SHADOW-ATC — Hardware Frontier

This document captures the SPEC-status frontier upgrades — items that
require silicon, optics, or cleanroom infrastructure rather than code.
Each entry lists what to procure, the acceptance test, the vendor
shortlist, and how the deliverable plugs into the existing protocol.

The CODE / HOOK frontier upgrades live in
[05-frontier-upgrades.md](05-frontier-upgrades.md) and the
[ground-station/](../ground-station/) crate.

---

## §5. Masked / Threshold-Protected ML-KEM + ML-DSA Silicon

**Threat addressed.** First-order (and ideally second-order) DPA / EM
side-channel extraction of secret intermediates during ML-KEM
keygen + decapsulation and ML-DSA signing.

**Requirement.** All NIST-PQ secret operations execute inside a masked
coprocessor where every intermediate is split into ≥ 2 shares whose
joint distribution is independent of the secret. Mask refresh fires
on every operation.

**Acceptance test.**
- TVLA on 1M traces: |t| < 4.5 across the entire computation window.
- ISO/IEC 17825 + 20085 EM side-channel test campaign at an accredited
  lab (Brightsight, Riscure, NCC Group).
- Differential fault analysis: ≥ 99 % fault detection on transient
  voltage/clock glitches across 100 k injections.

**Vendor shortlist.**
- **PQShield PQPlatform-CoPro** — first-order masked ML-KEM/ML-DSA on
  RISC-V coprocessor IP. License + ASIC integration.
- **Crypto Quantique QDID** — masked PQ + integrated PUF (covers §15).
- **Rambus CryptoCore-300** — masked AES + masked PQ extension.
- **Secure-IC Securyzr** — mask refreshing for ML-DSA + dual-rail logic
  for the AES core (covers §16).

---

## §6. Active-Mesh Tamper Response with Sub-µs Zeroization

**Threat addressed.** Physical decapsulation, drilling, prying, voltage
manipulation, freezing, X-ray imaging.

**Requirement.**
- 4-layer active mesh wraps every cryptographic IC and key store.
- Trip threshold: < 1 µs from breach detection to CSP zeroize complete.
- Capacitor backup ≥ 50 ms continuous trip-circuit power after AC cut.
- Light, motion, temperature (≤ -20 °C and ≥ +85 °C), pressure
  (vacuum and over-pressure) — all trip the mesh.

**Acceptance test.**
- FIPS 140-3 Level 4 physical security testing campaign at an
  accredited lab.
- Probe-trip latency measured on a hardware test point: ≤ 1 µs from
  mesh continuity break to zeroize complete.
- Cold-attack: chip immersed in liquid nitrogen → mesh trips first.

**Vendor shortlist.**
- **Thales Luna HSM 7 / Network HSM 10** — FIPS 140-3 L4 candidate
  with active mesh.
- **Utimaco SecurityServer Se Gen2 CP5** — Common Criteria EAL4+
  evaluated, active mesh shipping.
- **Marvell LiquidSecurity 2** — for cloud-edge deployment.

---

## §7. Entanglement-Based QKD (E91)

**Threat addressed.** Detector-blinding attacks on prepare-and-measure
QKD (BB84). Provides device-independent security.

**Requirement.** Both ground sites in a peering pair receive one half
of an entangled photon pair from a central source. Bell-CHSH inequality
violation is verified per session window; if violation < 2.0, the
session aborts and falls back to all-PQ.

**Acceptance test.**
- Sustained CHSH > 2.4 over a 48 h continuous run on the production
  fiber.
- Side-channel red-team: detector blinding attempts produce
  CHSH ≤ 2.0 and trip an abort.
- Key delivery rate ≥ 1 kbit/s after privacy amplification.

**Vendor shortlist.**
- **Qunnect Q-LION** entangled-pair source.
- **ID Quantique XGR-DI** (in development) — when shipping.
- **Toshiba Twin Field QKD** — multi-node alternative.

---

## §8. Measurement-Device-Independent QKD (MDI-QKD)

**Threat addressed.** Side-channel attacks on the trusted measurement
hardware in a hub-and-spoke QKD topology. Allows COTS detectors.

**Requirement.** Each ground site sends weak coherent pulses to a
central Bell-state measurement node that may be untrusted. Security
is established via the BSM outcomes regardless of the BSM hardware.

**Acceptance test.** Same key delivery rate target as §7. The BSM is
red-teamed: a deliberately compromised BSM may not lower the
end-to-end secret-key rate below the protocol's lower bound.

**Vendor shortlist.** **ID Quantique Cerberis** with MDI extension,
**QuantumCTek**.

---

## §14. Logic Locking with Anti-SAT Obfuscation

**Threat addressed.** Captured ASIC or FPGA bitstream is reverse-engineered
and embedded secrets are extracted.

**Requirement.** SARLock or Anti-SAT lock embedded in the
cryptographic ASIC layout. Without the unlock key, the netlist
appears as random combinational logic.

**Acceptance test.**
- SAT attack with a random-pattern PIP (Path-In-Path) generator: 10⁹
  queries fail to converge.
- Functional test with the wrong unlock key: 100 % of test vectors
  produce incorrect outputs.
- Side-channel test on the unlock-key path: |t| < 4.5 to prevent the
  unlock from leaking.

**Vendor shortlist.** **Tortuga Logic Radix-S** (verification),
**MENTA eFPGA** (locked eFPGA IP), **SecureRF** (custom Anti-SAT).

---

## §16. Glitch-Free Cryptographic Coprocessor (Dual-Rail)

**Threat addressed.** Power-trace correlation attacks (CPA) at the
gate level. Single-rail logic leaks because each toggle has a
data-dependent direction.

**Requirement.** Crypto coprocessor implemented in dual-rail
precharge logic (DRP), so every clock cycle every gate exits the
precharge phase, executes one transition, and returns to precharge
regardless of secret values. WDDL or MDPL macro library.

**Acceptance test.** TVLA on 10 M traces with the production silicon,
window-aligned to ML-KEM and ML-DSA paths: |t| < 4.5 throughout.

**Vendor shortlist.** **Secure-IC Securyzr** (DRP-capable),
**Riscure** (red-team verification).

---

## §17. Byzantine Fault Tolerance for the Ground Network

**Threat addressed.** Up to ⌊(n-1)/3⌋ ground stations malfunctioning
or actively malicious — partition attacks, conflicting commands,
double-spend of clearance numbers.

**Requirement.** Inter-site coordination protocol with provable
liveness and safety under Byzantine assumptions, sub-second commit
latency, integrated into the audit chain (#22).

**Recommendations.**
- **HotStuff-2** for ATC consensus — well-studied, ~ 200 ms commit on
  a 7-node WAN.
- **DAG-Rider** if higher throughput is required.
- **Mysticeti** for sub-100 ms commits at the cost of more bandwidth.

The chosen consensus layer signs each block with a threshold ML-DSA
signature (#4). Implementation lives outside this codebase — the
ground-station daemon's `audit.rs` is designed to consume blocks
once they are committed.

---

## §19. Side-Channel-Resistant Error Correction

**Threat addressed.** Cache-timing and memory-access pattern leakage
during error-correction operations on secret data (e.g., ML-KEM CT
correction, RPSS reconstruction).

**Requirement.**
- All branches that depend on secret data are eliminated; conditionals
  are replaced with constant-time selects.
- Lookup tables are accessed with secret-independent addressing.
- The memory controller randomizes access ordering at the cache-line
  granularity.

**Acceptance test.**
- `dudect` run over 1M paired traces of `aead_open` and `knock_token`:
  Welch t-statistic |t| < 4.5.
- Cache-side-channel test (Flush+Reload, Prime+Probe) on a colocated
  process: 0 bits of secret recovered over 24 h continuous run.

**Code state.** Constant-time properties already hold for
[`crypto.rs`](../ground-station/src/crypto.rs) and
[`knock.rs`](../ground-station/src/knock.rs); RustCrypto's
`aes-gcm`, `ml-kem`, `ml-dsa` are constant-time over secrets. This
section governs the production hardware build; the test acceptance
applies to the deployed binary on its target hardware.

---

## Procurement matrix

| Frontier item | Vendor 1                | Vendor 2              | Vendor 3              | Lead time | Acceptance lab           |
| ------------- | ----------------------- | --------------------- | --------------------- | --------- | ------------------------ |
| §5 Masked PQ  | PQShield                | Crypto Quantique      | Rambus                | 12 mo     | Brightsight              |
| §6 Active mesh| Thales Luna 7           | Utimaco Se Gen2 CP5   | Marvell LiquidSec 2   | 6 mo      | atsec                    |
| §7 E91 QKD    | Qunnect                 | ID Quantique XGR-DI   | Toshiba TF-QKD        | 24 mo     | NIST quantum prog.       |
| §8 MDI-QKD    | ID Quantique Cerberis   | QuantumCTek           | Toshiba               | 12 mo     | NIST quantum prog.       |
| §14 Logic lock| MENTA eFPGA             | Tortuga Logic         | SecureRF              | 18 mo     | UMD ECE                  |
| §16 Dual-rail | Secure-IC Securyzr      | PQShield (DRP variant)| Rambus                | 18 mo     | Riscure                  |
| §17 BFT       | HotStuff-2 (in-house)   | DAG-Rider             | Mysticeti             | 9 mo      | independent academic     |
| §19 SCA-ECC   | Riscure (verification)  | Brightsight           | NCC Group             | 6 mo      | Brightsight              |
