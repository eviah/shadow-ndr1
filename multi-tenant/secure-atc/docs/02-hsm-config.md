# SHADOW-ATC · HSM and Hardware Root-of-Trust Configuration

> *Software you can patch. Fuses you cannot. The system is no stronger
> than the layer that cannot be lied to.*

This document specifies the hardware roots of trust on both ends of
SHADOW-COMM: the ground-station HSM, the aircraft transponder TPM, and
the OTP fuse map that locks down policy at the silicon level.

---

## 1. Ground-station HSM

### 1.1 Form factor and certification

| Property | Requirement |
|---|---|
| Standard | FIPS 140-3 Level 4 |
| Certification | Common Criteria EAL 7 (or NIAP CSfC PP for HSMs at equivalent assurance) |
| Form factor | PCIe card or network HSM in shielded chassis inside the Faraday cage |
| Tamper response | Active mesh + voltage/temperature sensors → on tamper, instant zeroize of all CSPs and OTP-burn of an "evidence" fuse |
| Quantum-readiness | Native CRYSTALS-Kyber and CRYSTALS-Dilithium primitives in firmware (not via JIT-loadable plugin) |
| RNG | Two independent hardware entropy sources, SP 800-90B health-tested, output through SP 800-90A DRBG |

The HSM is the only component permitted to read or write the long-term
keys. The application code holds **opaque key handles**, never raw key
material.

### 1.2 Object inventory

The HSM stores the following objects. Each is labelled with a stable
PKCS#11 `CKA_LABEL`:

| Label | Type | Use | Exportable? |
|---|---|---|---|
| `gs/longterm/sig` | Dilithium-5 keypair | Sign Phase-2 KEM_OFFER | Public part only, under operator dual control |
| `gs/longterm/sig.prev` | Dilithium-5 keypair | Verify legacy peers during a key-rotation grace window | Public only |
| `enrol/{id_A}/pk` | Dilithium-5 public key | Verify aircraft Phase-3 KEM_RESP | n/a (public) |
| `enrol/{id_A}/k_master` | 256-bit symmetric | HMAC for knock-token derivation | NEVER |
| `policy/fuse-readback` | 64 bytes | Cached read of OTP fuse bank, for boot-time check | n/a |
| `monitor/diode/key` | Dilithium-5 keypair | Sign telemetry sent over the data diode (§6 of arch) | Public only |

The wildcards `{id_A}` mean "one entry per enrolled aircraft." A typical
fleet of 200 aircraft therefore has 400 enrolment objects.

### 1.3 Key custody and operator roles

The HSM is partitioned into **roles**, each authenticated by a separate
operator card. No single role can perform a security-critical action.

| Role | Card holder | Powers |
|---|---|---|
| `ENROL_A` | Enrolment officer A | Add/remove aircraft enrolment objects (with `ENROL_B`) |
| `ENROL_B` | Enrolment officer B | Same as above; both required |
| `KEY_ROTATE` | Crypto custodian (× 2 of N share) | Rotate `gs/longterm/sig`. Requires both halves of a Shamir 2-of-N split |
| `AUDIT` | Auditor | Read access logs, no key access |
| `SO`     | Security Officer | HSM lifecycle, firmware load (also requires factory signature) |
| `ZEROIZE` | Two custodians (k=2 of N) | Trigger emergency zeroize |

No role has the power to *read* the value of `enrol/*/k_master` or any
private signing key. They can only authorize *operations* (sign, decap,
HMAC) the HSM performs internally.

The `ENROL_*` and `KEY_ROTATE` operations require **two operators
present in the room, on separate consoles, within a 30 s window**
(architecture §5). The HSM enforces the timing in firmware.

### 1.4 Aircraft enrolment ceremony

To add a new aircraft to the network, **and only inside the enrolment
cage** (a shielded room separate from the operational ground station):

1. The aircraft's transponder HSM is freshly provisioned by the
   manufacturer with a Dilithium-5 keypair `(pk_A, sk_A)`. `sk_A` never
   leaves the chip.
2. A 256-bit `K_master[A]` is generated **inside the enrolment HSM** —
   not by software, not by the operator, not by the manufacturer. The
   enrolment HSM exports it ONLY into:
   - the aircraft TPM via a one-shot wrapped-key channel (§2 below), and
   - the operational ground HSM via a separate one-shot channel.
   In both cases the wrapping key is single-use and is destroyed
   immediately after.
3. `pk_A` is signed by `gs/longterm/sig` to produce an **enrolment
   certificate**. The certificate, but not `K_master[A]`, is replicated
   to all peer ground stations in the region.
4. Both operators `ENROL_A` and `ENROL_B` countersign an entry in the
   append-only access log; the entry includes the aircraft tail number,
   transponder serial, and a hash of `pk_A`.
5. The transponder is sealed in a tamper-evident bag with the operators'
   wax seals; only the airframe maintenance officer breaks the seal at
   installation.

**At no point is `K_master[A]` available in plaintext to any human.** The
two operators each hold cryptographic confirmation that the ceremony
ran; neither holds the secret.

### 1.5 Key rotation

`gs/longterm/sig` rotates on a 12-month schedule, or on demand after
suspected compromise.

- Rotation requires two `KEY_ROTATE` operators (Shamir 2-of-N split of
  the rotation authorization).
- The new public key is signed by the old key (a forward-chained
  certificate); aircraft accept the new key when they observe a
  signed transition message during a handshake — the message is
  countersigned by both old and new keys.
- A 7-day grace window allows aircraft that haven't seen the
  transition to still verify against the old key. After the grace
  window the old key is zeroized in the HSM.
- `enrol/*/k_master` rotates per-aircraft on either:
  - tail-number transfer of ownership,
  - any maintenance event that opens the transponder housing, or
  - 36 months elapsed.

Rotation never weakens the security property — during the grace window,
the **strictest** policy applies (an aircraft must satisfy both old and
new criteria, not either).

---

## 2. Aircraft transponder TPM

The aircraft side does not need a full HSM. It needs a **single-purpose
crypto die** with the following properties:

| Property | Requirement |
|---|---|
| Form factor | Discrete die in the transponder LRU, separate package and clock from the avionics CPU |
| Power | Independent regulator, brown-out detection, zeroize on under-voltage |
| Memory | OTP region for `K_master[A]`, `(pk_A, sk_A)`, and per-aircraft fuse map; volatile RAM for session keys, zeroized on power loss |
| Anti-rollback | Monotonic counter incremented on every firmware load attempt; firmware must present a counter ≥ stored value |
| RNG | On-die ring-oscillator + thermal noise, conditioned through SHAKE-256 |
| Tamper | Mesh + light sensors; on tamper, OTP-burn an "evidence" fuse and zeroize RAM |
| Certification | At minimum FIPS 140-3 Level 3, preferred Level 4 |

The crypto die exposes only a narrow command set over a dedicated SPI
bus to the avionics CPU:

```
KNOCK_DERIVE(bucket B)            -> 8-byte token
KEM_DECAP(ct)                     -> ss
HKDF_DERIVE(label, info)          -> session key (kept inside die)
AEAD_ENCRYPT(dir, seq, aad, pt)   -> ct||tag
AEAD_DECRYPT(dir, seq, aad, ct||tag) -> pt | FAIL
SIGN(payload)                     -> sig_A
ATTEST()                          -> measurement-bound attestation blob
ZEROIZE()                         -> wipes session state
```

Note: there is no `EXPORT_KEY` command. Session keys live and die inside
the crypto die. The avionics CPU encrypts and decrypts by sending
plaintext or ciphertext across the SPI bus; **plaintext keys never
appear on the bus**.

The crypto die boots from immutable mask ROM, which loads measured
firmware into RAM, hashes it, and refuses to run if the hash disagrees
with an OTP-burned reference. Firmware updates are possible but require:
- a manufacturer signature,
- a higher anti-rollback counter than the stored value, and
- a valid `KEY_ROTATE`-equivalent signature from the airline's enrolment HSM.

---

## 3. OTP fuse map

The OTP fuses are the **last word**. The runtime config can never relax
a policy that the fuses set; the runtime AND's its config with the fuse
map at boot.

### 3.1 Ground station fuse bank

| Offset | Bits | Field | Value at factory |
|---|---|---|---|
| 0x00 | 8  | Protocol version | `01` |
| 0x01 | 8  | Cipher suite | `01` (Kyber-1024 + Dilithium-5 + AES-256-GCM + HKDF-SHA3-512) |
| 0x02 | 16 | Replay window size | `256` |
| 0x04 | 8  | Knock window seconds | `30` |
| 0x05 | 8  | Handshake clock skew tolerance s | `5` |
| 0x06 | 8  | Session clock skew tolerance s | `3` |
| 0x07 | 16 | Rekey interval seconds | `30` |
| 0x09 | 16 | Idle timeout seconds | `90` |
| 0x0B | 8  | Lockout strikes | `3` |
| 0x0C | 16 | Lockout window seconds | `60` |
| 0x0E | 16 | Lockout hold seconds | `600` |
| 0x10 | 16 | RF cone half-angle deci-degrees | `15` (= 1.5°) |
| 0x12 | 16 | RF sidelobe minimum dB | `40` |
| 0x14 | 16 | RF in-band threshold deci-dBm | `-900` (= -90.0 dBm) |
| 0x16 | 16 | RF blackout duration seconds | `60` |
| 0x18 | 32 | Boot measurement reference (low) | manufacturer-defined |
| 0x1C | 32 | Boot measurement reference (high) | manufacturer-defined |
| 0x20 | 1  | Allow remote management | `0` (NEVER) |
| 0x20 | 1  | Allow firmware downgrade | `0` |
| 0x20 | 1  | Allow cipher renegotiation | `0` |
| 0x20 | 1  | Tamper evidence already burned | `0` (becomes `1` on first tamper) |
| ...  |    | reserved-zero | `0` |

The boot loader reads the fuse bank, computes the runtime config from
the loaded firmware, and **AND**'s every numeric tolerance with the fuse
value (using the *more restrictive* of the two). For booleans, the fuse
forces the value to false if the fuse says false.

If the fuse `Tamper evidence already burned == 1`, the security
processor refuses to boot. The HSM and crypto die are physically
replaced before service resumes.

### 3.2 Transponder fuse bank

The aircraft transponder has a smaller fuse bank with the same general
shape, plus:

| Offset | Bits | Field | Value at factory |
|---|---|---|---|
| 0x30 | 64 | Aircraft id (`id_A`) | per-airframe |
| 0x38 | 16 | Steering error cutoff deci-degrees | `10` (= 1.0°) |
| 0x3A | 16 | Maximum TX power dBm | per-airframe per slant-distance class |
| 0x3C | 8  | Allow listen-only fallback | `1` |
| 0x3D | 8  | Mandatory hop pattern derivation | `1` (always derive from session key) |

The transponder firmware reads these at boot and refuses to start if
the loaded firmware tries to override any of them.

---

## 4. Firmware load policy

| Action | Permission required |
|---|---|
| Read public keys | None (they're public) |
| Read fuse bank | None (it's the policy, not a secret) |
| Read access log | `AUDIT` role |
| Add aircraft enrolment | `ENROL_A` AND `ENROL_B`, both within 30 s |
| Remove aircraft enrolment | `ENROL_A` AND `ENROL_B` |
| Rotate `gs/longterm/sig` | `KEY_ROTATE` × 2 (Shamir split) |
| Load HSM firmware | Manufacturer signature + `SO` + `KEY_ROTATE` × 2 |
| Load ground-station firmware | Vendor signature + boot-measurement matches OTP reference |
| Zeroize | `ZEROIZE` × 2 within 30 s — and any tamper triggers it automatically |
| Burn additional OTP bits | `SO` + `KEY_ROTATE` × 2 + manufacturer one-shot card |

**There is no path for any single human to load arbitrary firmware.**
There is no path for any human, alone or together, to read raw
`K_master[A]` or any private signing key.

---

## 5. Boot sequence

Cold boot, ground station:

```
0   Power-on; HSM self-test (RNG, AES, SHA3, Kyber, Dilithium KAT).
0.1 Boot ROM loads stage-1 from flash; measures it into HSM PCR-0.
0.2 Stage-1 verifies its own signature against an OTP-burned vendor
    public key. Mismatch → halt, refuse to energize radio.
1   Stage-1 loads stage-2 (ground-station daemon) and measures into
    PCR-1. Verifies signature.
2   Daemon reads OTP fuses, builds runtime config = AND(loaded config,
    fuse). Mismatch in any non-relaxable field → halt.
3   Daemon attests boot to silent monitoring plane (one-way diode).
4   Daemon brings up dark-fibre interface in listen-only mode.
5   Daemon brings up radio in listen-only mode (RX yes, TX muted).
6   Daemon waits 30 s, observes its own RF environment, validates
    Faraday cage integrity against the silent monitoring telemetry.
7   Daemon enters Phase 0 (quiescent listen). Service is up.
```

If any step fails, the daemon does not retry — it halts. A halted
ground station is recovered by §10 disaster recovery.

Cold boot, transponder, is structurally identical but smaller (about
1.2 s wall-clock).

---

## 6. Live access logging

Every HSM operation produces a log entry: timestamp, role,
operation, object label, result. Entries are:

1. Hash-chained — entry N includes `SHA3-512(entry N-1)` so reordering
   or deletion is detectable.
2. Signed by `gs/longterm/sig` per entry.
3. Mirrored simultaneously to:
   - a write-once optical jukebox in the ground-station building,
   - a serial-line thermal printer producing a perforated paper roll
     (sealed at every shift change in dated evidence bags),
   - the silent monitoring plane via the one-way diode.

A discrepancy between any two of these three sinks is by itself a
high-severity event and forces a §10 DR rotation.

The thermal printer matters: an attacker who compromises the network
attack surface still cannot edit the paper roll. The roll is the
ground truth.

---

## 7. What the HSM does NOT do

For the avoidance of doubt:

- It does not export private keys, ever, to anyone, for any reason. A
  "key escrow" feature is not provided.
- It does not authenticate humans by password alone. Cards are required.
- It does not have a "factory reset" command. End-of-life is physical
  destruction (drilled, shredded, smelted).
- It does not run general-purpose code. Custom firmware is not loadable
  in the field.
- It does not communicate with the public Internet. The HSM has a single
  PCIe link to the security processor; that processor has a single
  fibre link to the rest of the operational plane; that fibre has
  no IP route off-site.
