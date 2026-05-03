# SHADOW-ATC · Architecture Blueprint

> *"The lock is hard to pick. The door is harder to find. And the building
> is not on any map."*

The system is layered so that a defect in any one layer cannot, by itself,
expose communications. Each layer below assumes the layer above it has failed.

---

## 0. Threat model

| # | Adversary | Capabilities assumed | Defense layer of last resort |
|---|---|---|---|
| T1 | Nation-state SIGINT | Unlimited spectrum monitoring, satellite, spoofers, cryptanalysis budget | §1 RF discipline, §3 PQ crypto |
| T2 | Cyber actor on terrestrial Internet | Full Internet routing, exploit chains, supply chain | §2 air gap |
| T3 | Compromised vendor / supply-chain | Backdoored firmware, malicious updates | §6 attestation, §7 hardware fuses |
| T4 | Insider with legitimate access | Operator credentials, physical site entry | §5 two-person, §7 fuse-locked policy |
| T5 | Coercion / social engineering of operators | A single operator can be compelled | §5 two-person, §6 dual control |
| T6 | Physical site assault | Building penetration, hardware seizure | §7 zeroize, §10 DR |

The success criterion (§13) is met only if T1+T2 cannot determine that
communication is taking place on the target frequencies. Lower-numbered Ts
(T3–T6) are contained but not necessarily defeated by software alone.

---

## 1. Physical layer · Air-Gap+

**Spectrum discipline**

- Aircraft↔ground link uses a **directional phased-array** transmitter. The
  beam is steered toward the known position of the receiving ground station
  (computed from the aircraft's filed flight plan and continually refined from
  ADS-B-In ground references). Beamwidth ≤ 3°, sidelobe suppression ≥ 40 dB.
- Power is **range-limited** to the exact slant distance to the ground station
  +6 dB margin. Any extra dB is information leakage and is not transmitted.
- Frequency hopping over a pre-shared 1024-channel schedule per session;
  schedule is derived from the session key (so an observer who sniffs one
  channel sees nothing but periodic noise).

**Wireline discipline**

- Ground stations are connected to ATC core via **dedicated dark-fibre** in
  tamper-detecting conduit (continuous OTDR monitoring + loose-tube laser
  interlock). Any optical disturbance triggers §10 DR.
- The dark-fibre network has **no IP route** to the public Internet. Not a
  default-deny firewall — *no route entry exists*. A compromised host on the
  ATC network has nothing to dial out to.

**Site discipline**

- Ground stations are **Faraday-shielded** (≥ 80 dB attenuation, 100 MHz–18 GHz).
- All cabinet penetrations use ferrite-loaded waveguide-below-cutoff vents.
- Power enters through filtered isolation transformers; no signal can ride
  the mains out.

**Active denial**

- Any received signal **outside the expected directional cone** with strength
  > −90 dBm at the antenna triggers a 60 s transmission blackout. The
  blackout is silent — no alert is radiated.
- A passive RF survey runs continuously; out-of-band emitters within 500 m
  are recorded to the §6 monitoring plane (not to the operational plane).

---

## 2. Logical layer · Zero trust, ephemeral everything

- **No persistent sessions.** Every flight produces a brand-new key bundle.
  Closing the canopy zeroizes everything.
- **No persistent tokens.** Every wire frame is independently authenticated
  (AES-256-GCM AAD includes monotonic seq + aircraft id + UTC second).
- **No remote management.** Maintenance requires physical site presence,
  badge + biometric + hardware key (§5). There is no SSH, no VPN, no remote
  console — those are not "disabled," they are *not built in*.
- **Hardware-fused security policy.** Cipher suite, key sizes, lockout
  thresholds, rekey interval, knock window length are written to one-time-
  programmable (OTP) fuses on the security processor at factory install. They
  cannot be changed in the field. A field firmware update cannot relax any
  policy stricter than the fuse — fuses are AND'd over the runtime config.

---

## 3. Crypto layer · Quantum-resistant primitives

- **KEM**: CRYSTALS-Kyber-1024 (NIST PQC selected, level 5). Used during knock
  and at every 30 s rekey.
- **Signatures**: CRYSTALS-Dilithium-5. Ground stations are pinned to the
  aircraft transponder's long-term public key at fleet enrollment; the
  aircraft pins the ground network's long-term public key at provisioning.
- **AEAD**: AES-256-GCM with hardware acceleration (AES-NI / ARM Crypto Ext).
- **KDF**: HKDF-SHA3-512.
- **Replay window**: 256 packets, monotonic 64-bit sequence in AAD.
- **Forward secrecy**: full Kyber re-encapsulation every 30 s. Old session
  key is overwritten with `memset_explicit` immediately after the new key
  is derived. Capture-and-decrypt-later is defeated even if one rekey leaks.

The cryptographic protocol is specified in detail in
[`01-crypto-protocol.md`](01-crypto-protocol.md).

---

## 4. Network obscurity · The system that isn't there

- The ground station has **no advertised endpoint**. No DNS, no service
  discovery, no SSDP, no mDNS. The radio receiver listens to the air; the
  fibre interface listens on a single UDP port that drops every packet that
  fails the §1 directional check before any Layer-4 work is done.
- **No Layer-3 acknowledgements** of any kind to unauthenticated traffic.
  An observer scanning the band sees thermal noise. An observer scanning
  the fibre — which they shouldn't be able to reach physically — sees a
  black hole.
- The first 8 bytes of any aircraft frame must match the **time-windowed
  knock token** (§5 of the protocol spec). A frame whose token does not
  match in either of the current or previous 30 s windows is dropped at the
  packet decoder, before any state is allocated.
- No log line is written for failed knocks on the operational plane. The
  silent-IDS plane (§6) records them out-of-band.

If a nation-state SDR sweeps the band, it sees noise. If it has a stolen
key and tries to knock, but at the wrong time, it sees nothing. If it's on
the wrong heading from the antenna, it sees nothing. There is no
interactive surface to probe.

---

## 5. Human access · Two-person, fuse-locked

- **Physical room access**: badge + iris + voiceprint + fingerprint + PIN.
  All five must agree against the local enrolment HSM. Centralized
  authentication does not exist.
- **Two-person rule (k = 2 of N)**: any operator action on the security
  policy or key custody requires two distinct authenticated operators
  present in the room and active on separate consoles, within a 30 s window.
  Shamir-2-of-N split applied to the maintenance key.
- **No security-relevant settings can be changed in software**. Cipher
  suite, lockout thresholds, knock window, rekey interval, max session
  lifetime — all live in OTP fuses (§2).
- **Append-only access log** mirrored to (a) a write-once optical jukebox
  and (b) a serial line printer that prints to a perforated thermal roll.
  The roll is sealed in a dated evidence bag at every shift change and
  stored off-site.

---

## 6. Silent monitoring · See without being seen

The monitoring plane is **physically separate** from the operational plane.
Sensors observe; they do not interact. A compromise of the monitoring plane
cannot compromise communications.

Sensors:
- RF spectrum survey (passive, 100 MHz – 18 GHz)
- Optical OTDR on every fibre run (continuous)
- Power-line current signature monitor (against EM injection)
- Knock decoder failure counter, per-aircraft and per-direction
- Faraday-cage door interlocks, vibration sensors, thermal cameras

Telemetry leaves the site over a *separate* one-way diode link to the
NDR core. The diode is a literal optical isolator with no return path.
Detection that an attack happened cannot inform the attacker that we
detected them, because the detection signal can't reach them.

See [`03-monitoring.md`](03-monitoring.md).

---

## 7. Hardware roots of trust · HSM and OTP

- **HSM**: FIPS 140-3 Level 4, common-criteria EAL 7. Holds the long-term
  Dilithium keypair, the per-aircraft enrolment hashes, and the master
  knock-token derivation key. Tamper response: zeroize.
- **OTP fuses**: cryptographic policy values burned at factory. The runtime
  reads them at boot and refuses to start if it disagrees with them.
- **Secure boot**: every code stage measured into the HSM; any unmeasured
  byte halts the machine before the radio is energized.
- **Attestation**: the ground station signs a boot-time attestation
  containing all measurements; the attestation is consumed only by the
  silent monitoring plane (out-of-band).

See [`02-hsm-config.md`](02-hsm-config.md).

---

## 8. Aircraft side

The aircraft transponder has its own miniature HSM (TPM-class with PQ
extensions) holding:
- The aircraft's Dilithium long-term keypair.
- The shared knock-derivation key (per-aircraft, provisioned in the
  enrolment cage, never leaves the chip).
- A monotonic counter for replay defence.

The transponder firmware boots from immutable mask ROM into a measured
loader. The crypto module is in a separate die with its own clock, its
own RAM, and its own power domain. A failure of the avionics computer
cannot leak transponder keys.

The transponder's directional emitter steers using GPS + INS fused with
the published locations of authorized ground stations. If the steering
error exceeds 1° the transmitter cuts (because emitting in the wrong
direction is a leak).

---

## 9. Latency budget

The 50 ms ATC safety bound is met by:
- Knock decode: < 50 µs (HMAC-SHA3 over 8 bytes + table lookup).
- Kyber-1024 decap on aircraft hardware: < 1 ms; on ground HSM: < 200 µs.
- Dilithium-5 verify: < 2 ms.
- AES-256-GCM at full duplex: < 5 µs per frame on AES-NI / ARM Crypto Ext.
- Fibre + radio one-way: site-dependent, typically ≤ 20 ms.

Steady-state per-packet authenticated transmission cost is well under
10 ms. The 50 ms budget binds during the initial handshake, which happens
once per flight before the first ATC message and is overlapped with
clearance delivery.

---

## 10. Disaster recovery

If the room is breached, if a Faraday seal fails, if an HSM tamper switch
fires, the system follows a strict zeroize-and-physical-rotate playbook.
There are **no remote backdoors** to recover with. A breach means a
physical key custodian flies to the affected site with sealed hardware.

See [`04-disaster-recovery.md`](04-disaster-recovery.md).

---

## 11. Redundancy

- Each ATC region has ≥ 3 ground stations on widely separated sites with
  uncorrelated power and fibre paths.
- Each ground station has ≥ 2 redundant antennae with non-overlapping
  beam coverage of the airspace.
- Each ground station has dual independent power: utility + on-site DC
  battery + diesel; the security processor runs from a separate UPS that
  cannot be reached from the maintenance bus.
- Failover does not require any cross-site coordination. Aircraft transponder
  selects the strongest-signal ground station within the flight envelope
  using a hash-based prioritization, and re-knocks. There is no shared
  cluster state to compromise.

---

## 12. Code-level discipline

- Ground station: Rust, `#![forbid(unsafe_code)]` at crate root; the only
  `unsafe` lives in vetted FFI shims to the HSM PKCS#11 binding and to
  AES-NI intrinsics, both behind narrow modules with explicit invariants.
- Transponder: a constrained subset of C compiled with `-Wall -Wextra
  -Werror -Wconversion -fstack-protector-strong -D_FORTIFY_SOURCE=2
  -fsanitize=undefined,address` for development, and CompCert (or a Frama-C
  ACSL pass) for the production build.
- Both sides run continuous fuzzing of the wire decoder before a build is
  flashed.
- No `printf` family on the production transponder — logging is
  binary-encoded into the §6 telemetry stream so that no string ever
  becomes a side-channel.

---

## 13. Success criterion

A nation-state actor with unlimited resources, parked outside the perimeter
with a phased-array SIGINT array and quantum-class compute, performs:

1. Multi-band passive listening — sees only thermal noise.
2. Active probing — sees no replies, no error responses, nothing on which
   to inform a model.
3. Crypto-attack on captured ciphertext — Kyber-1024 + AES-256-GCM under a
   30 s rekey is the wrong target for any current or near-future quantum
   adversary.
4. Supply chain — finds OTP fuse policy disagreement, refuses to boot.
5. Insider — sees only their share of the 2-of-N split.

**There is no door to knock on. So no one knocks.**
