# SHADOW-COMM v1 · Cryptographic Protocol Specification

> *Silence before handshake. Handshake before session. Session before message.
> Anywhere along the chain, the answer to a wrong question is no answer at all.*

This document specifies the wire protocol used between an aircraft transponder
and a SHADOW-ATC ground station. The protocol is deliberately small — six
phases, one rekey loop, one termination path. Anything not listed here is
not part of the protocol and MUST be rejected.

Conventions: SHALL / MUST = mandatory. MAY = optional. All multi-byte fields
are big-endian. All time values are UTC TAI seconds (no leap-second slop).
"Zeroize" means `memset_explicit` followed by a memory-fence read-back.

---

## 0. Notation and primitives

| Symbol | Meaning |
|---|---|
| `K_master[A]` | Per-aircraft 256-bit pre-shared knock-derivation key. Burned into the aircraft HSM at enrolment; held in the ground HSM under operator dual control. |
| `(pk_A, sk_A)` | Aircraft long-term Dilithium-5 keypair. |
| `(pk_G, sk_G)` | Ground network long-term Dilithium-5 keypair. Pinned at provisioning. |
| `(epk, esk)` | Ephemeral Kyber-1024 keypair, ground-side. New per session and per rekey. |
| `ct` | Kyber-1024 ciphertext (1568 bytes). |
| `ss` | Kyber-1024 shared secret (32 bytes). |
| `K_s` | Session AES-256-GCM key (32 bytes), derived via HKDF. |
| `seq` | 64-bit monotonic frame counter, per session per direction. |
| `T` | Current UTC TAI second. |
| `id_A` | 64-bit aircraft identifier (the transponder serial, not the ICAO 24-bit). |
| `id_G` | 32-bit ground-station identifier. |

Primitives:
- KEM:        CRYSTALS-Kyber-1024 (FIPS 203, level 5).
- Signature:  CRYSTALS-Dilithium-5 (FIPS 204).
- Hash:       SHA3-512 and SHAKE-256 (FIPS 202).
- AEAD:       AES-256-GCM (FIPS 197 + SP 800-38D).
- KDF:        HKDF-SHA3-512 (RFC 5869 with SHA3-512).
- HMAC:       HMAC-SHA3-256 (FIPS 198-1).
- RNG:        DRBG seeded from at least two independent hardware entropy
              sources (HSM TRNG + on-die ring oscillator). Health-tested
              continuously per SP 800-90B.

---

## 1. Phase overview

```
   AIRCRAFT                                              GROUND STATION
   ────────                                              ──────────────
                       Phase 0 · Quiescence
                       (ground listens; no advertisement)

   ── Phase 1 · KNOCK ─────────────────────────────────▶ (verify ∈ ±W; else drop)
   ◀── Phase 2 · KEM_OFFER (Kyber pk + Dilithium sig) ── (allocate state ONLY now)
   ── Phase 3 · KEM_RESP (Kyber ct + Dilithium sig) ───▶
                       Phase 4 · session keys derived (HKDF)
   ◀══ Phase 5 · authenticated data (AES-256-GCM) ════▶
                       Phase 5b · 30-second rekey loop
   ── Phase 6 · CLOSE (signed, AEAD-protected) ────────▶ zeroize
```

Phases 1–4 complete in well under 50 ms on target hardware (§9 of the
architecture). Phase 5b runs forever until Phase 6 or until link loss.

---

## 2. Phase 0 · Quiescence

The ground station SHALL emit no carrier, no DNS, no service-discovery
beacon, no ARP-grat, nothing. It listens.

The radio receiver passes any in-cone, in-band frame to the knock decoder.
The fibre interface forwards any UDP datagram on the configured port to the
knock decoder. **No state is allocated** for either before the knock check
in §3 succeeds. There is no half-open table, no SYN backlog, no
`X-Forwarded-For` parsing, no JSON parser invoked.

A frame that fails the knock check is dropped silently and counted only on
the silent-monitoring plane (architecture §6). The operational plane writes
no log line, returns no ICMP, and does not update its own clock based on
the bad packet.

---

## 3. Phase 1 · KNOCK

### 3.1 Knock token

```
T_now   = current UTC TAI second
W       = 30                                  (window length, seconds)
B       = floor(T_now / W)                    (current bucket)

knock_token(B)  = HMAC-SHA3-256( K_master[A],
                                  "SHADOW-COMM/v1/knock"
                                || id_A
                                || id_G
                                || U64BE(B) ) [: 8 bytes ]
```

Only the first 8 bytes are transmitted. 8 bytes is enough: an attacker who
guessed it would still have to be in-cone, in-band, at the right antenna
heading, and within a 30 s window — and a successful guess only reaches
Phase 2, where Dilithium-5 stops them.

### 3.2 Frame format

```
0       1       2       3
+-------+-------+-------+-------+-------+-------+-------+-------+
|                       knock_token (8 bytes)                   |
+-------+-------+-------+-------+-------+-------+-------+-------+
|                       id_A (8 bytes)                          |
+-------+-------+-------+-------+-------+-------+-------+-------+
|        nonce_A (16 bytes — random, fresh per session)         |
|                                                               |
+-------+-------+-------+-------+-------+-------+-------+-------+
| ver=01| flags |        reserved=0 (must be zero)              |
+-------+-------+-------+-------+-------+-------+-------+-------+
```

Total: 36 bytes. `flags` bit 0 = "I am rejoining after RF blackout".

### 3.3 Verification

The ground station SHALL:

1. Recompute `knock_token(B)` and `knock_token(B-1)` (covers window slip
   ≤ 30 s). Constant-time compare. If neither matches → drop, count on
   silent plane, do not allocate.
2. Verify `ver == 0x01`, `reserved == 0`. Else → drop.
3. Verify the sender is in the expected directional cone (architecture §1).
   This check happens before the knock decode in software, but is restated
   here for completeness.
4. Verify `id_A` is in the active enrolment set held by the HSM. If not →
   drop. (The HSM lookup is constant-time over the enrolment set.)
5. Per-aircraft strike counter:
   - Successful knock → strike count := 0, proceed to Phase 2.
   - Failed knock with valid `id_A` shape → strike count += 1.
   - Strike count ≥ 3 within 60 s → that `id_A` is locked out for 600 s.
     Locked-out knocks are silently dropped. The lockout is held in HSM,
     not in software.

State is allocated only after step 4 passes. The allocation is a fixed-size
slot from a pre-sized array; there is no heap allocation in the knock path,
and no dynamic data structure whose size depends on attacker input.

---

## 4. Phase 2 · KEM_OFFER (Ground → Aircraft)

The ground station generates a fresh ephemeral Kyber-1024 keypair
`(epk, esk)`, signs the offer, and emits:

```
KEM_OFFER = {
    msg_type   : 0x10                        (1 byte)
    id_G       : 4 bytes
    epk        : 1568 bytes                  (Kyber-1024 public key)
    nonce_G    : 16 bytes                    (random, fresh)
    nonce_A    : 16 bytes                    (echo from KNOCK)
    timestamp  : 8 bytes UTC TAI seconds
    sig_G      : 4595 bytes                  (Dilithium-5 over the above)
}
```

`sig_G` is computed by the ground HSM with `sk_G` over the byte-string
`msg_type || id_G || epk || nonce_G || nonce_A || timestamp`.

The aircraft SHALL:

1. Verify `sig_G` against the pinned `pk_G`. Failure → drop, abort session,
   no retry on the same nonce.
2. Verify `nonce_A` matches the value it sent. Failure → abort.
3. Verify `|timestamp − T_aircraft| ≤ 5 s`. Failure → abort.
4. Verify `id_G` is in the aircraft's pinned ground-network set.

If all pass, the aircraft MUST proceed to Phase 3 within 200 ms. After
200 ms the ground station drops the half-session.

---

## 5. Phase 3 · KEM_RESP (Aircraft → Ground)

The aircraft performs Kyber-1024 encapsulation against `epk`:

```
(ct, ss) = KEM.Encap(epk)
```

`ss` (32 bytes) is the raw KEM shared secret. The aircraft signs the
response with its long-term Dilithium-5 key `sk_A`:

```
KEM_RESP = {
    msg_type   : 0x11
    id_A       : 8 bytes
    ct         : 1568 bytes                  (Kyber-1024 ciphertext)
    nonce_A    : 16 bytes
    nonce_G    : 16 bytes                    (echo from OFFER)
    timestamp  : 8 bytes
    sig_A      : 4595 bytes                  (Dilithium-5)
}
```

`sig_A = Dilithium.Sign(sk_A,  msg_type || id_A || ct || nonce_A || nonce_G || timestamp)`.

The ground station SHALL:

1. Verify `sig_A` against the pinned `pk_A` for this `id_A`. Failure →
   strike +1, abort, drop allocated state, zeroize `esk`.
2. Verify `nonce_G` matches the value it sent. Failure → abort.
3. Verify `|timestamp − T_ground| ≤ 5 s`. Failure → abort.
4. Decapsulate: `ss' = KEM.Decap(esk, ct)`. The decapsulation MUST be
   constant-time. The Kyber FO transform's implicit rejection is the only
   permitted error path.
5. Immediately zeroize `esk` (it is no longer needed and its lingering
   in memory weakens forward secrecy).

---

## 6. Phase 4 · Session key derivation

Both sides now hold the shared 32-byte secret. They derive session keys
using HKDF-SHA3-512:

```
salt   = SHA3-512( nonce_A || nonce_G )
ikm    = ss
prk    = HKDF-Extract(salt, ikm)

K_s_AG = HKDF-Expand(prk, "SHADOW-COMM/v1/A->G/key" || id_A || id_G, 32)
K_s_GA = HKDF-Expand(prk, "SHADOW-COMM/v1/G->A/key" || id_A || id_G, 32)

IV_AG  = HKDF-Expand(prk, "SHADOW-COMM/v1/A->G/iv"  || id_A || id_G, 12)
IV_GA  = HKDF-Expand(prk, "SHADOW-COMM/v1/G->A/iv"  || id_A || id_G, 12)
```

`K_s_AG` and `K_s_GA` are independent. A breach of one direction's key
does not yield the other. After expansion, `prk` and `ss` are zeroized.

The 12-byte IV per direction is the AES-GCM IV base. The actual per-frame
IV is `IV_dir XOR (4 zero bytes || U64BE(seq))`. NIST SP 800-38D's
unique-IV requirement is met because `seq` is monotonic and the session
is torn down before `seq` can wrap (≈ 1.8×10¹⁹ frames).

---

## 7. Phase 5 · Authenticated data

### 7.1 Frame layout

```
+-------+-------+-------+-------+
| ver=01| msg=20|       reserved=0 (2 bytes, must be zero)      |
+-------+-------+-------+-------+
|                       seq (8 bytes)                            |
+-------+-------+-------+-------+
|                       id_A (8 bytes)                           |
+-------+-------+-------+-------+
|                       id_G (4 bytes)                           |
+-------+-------+-------+-------+
|                       UTC second (8 bytes)                     |
+-------+-------+-------+-------+
|                       ciphertext (variable, ≤ 1200 bytes)      |
+-------+-------+-------+-------+
|                       auth_tag (16 bytes)                      |
+-------+-------+-------+-------+
```

The maximum 1200-byte payload keeps the frame below the typical aviation
data link MTU.

### 7.2 AEAD parameters

```
key   = K_s_AG          (or K_s_GA for the reverse direction)
iv    = IV_dir XOR (00 00 00 00 || U64BE(seq))
aad   = ver || msg || reserved || seq || id_A || id_G || UTC_second
ct||T = AES-256-GCM-Encrypt(key, iv, aad, plaintext)
```

The header is **the AAD**. Tampering with any header field invalidates
the tag.

### 7.3 Receive-side checks

The receiver SHALL, in this order, fail-closed at the first failure:

1. `ver == 0x01`, `msg == 0x20`, `reserved == 0`. Else drop.
2. `id_A`, `id_G` match the session. Else drop.
3. `|UTC_second − T_local| ≤ 3`. Else drop. (Tighter than the 5 s used
   during handshake, because the session is now established and clock
   skew has been measured.)
4. `seq` falls inside the **replay window** (§7.4). Else drop.
5. AEAD-Decrypt with the AAD as constructed. Authentication failure →
   drop, **strike +1**, do not surface plaintext to the application
   layer. Three strikes within 60 s tear down the session and trigger
   the §10 lockout.
6. Surface plaintext upstream.

### 7.4 Replay window

The receiver tracks the highest accepted `seq` (`seq_max`) and a 256-bit
bitmap of recent `seq` values relative to `seq_max`.

- `seq > seq_max + 2^31` → outright reject (large jumps are suspect).
- `seq > seq_max` → shift bitmap, set bit 0.
- `seq_max - 256 < seq ≤ seq_max` → look up bit; if already set →
  replay → drop & strike. Else set.
- `seq ≤ seq_max - 256` → too old → drop.

The replay window is per direction. It is held in static memory, never
reallocated, and is part of the zeroized session state on close.

---

## 8. Phase 5b · 30-second rekey

Every 30 s of session lifetime (driven by either side's clock; the first
to reach the deadline initiates) the protocol performs a fresh Kyber-1024
KEM round inside the existing session.

```
REKEY_OFFER  (G→A)  msg_type 0x30, contents identical to Phase 2 KEM_OFFER
                    but encapsulated as a Phase-5 AEAD frame (so the
                    rekey itself is forward-secret on the prior K_s).
REKEY_RESP   (A→G)  msg_type 0x31, mirror of Phase 3.
```

After a successful rekey:

1. Both sides derive a new `(K_s_AG', K_s_GA', IV_AG', IV_GA')` using the
   same HKDF labels, but with the new `ss` and fresh `nonce_A`/`nonce_G`.
2. `seq` resets to 0 in each direction (the IV uniqueness requirement
   resets with the key).
3. The previous keys, IVs, and `prk` are immediately zeroized. **A
   single rekey leak does not expose past or future traffic.**
4. The rekey itself is logged on the silent monitoring plane only.

If a rekey fails (sig fail, decap fail, AEAD fail), the receiving side
does NOT fall back to the old keys. The session is torn down and the
aircraft must re-knock from Phase 1.

---

## 9. Phase 6 · Termination

Either side may end the session by sending:

```
CLOSE = AEAD-protected frame, msg_type 0x40,
        plaintext = sig_dir(  "SHADOW-COMM/v1/close"
                            || id_A || id_G || final_seq || reason )
```

`reason` is one byte: 0x00 normal, 0x01 lockout, 0x02 hardware tamper,
0x03 link timeout, 0x04 RF blackout retained.

On receipt of a valid CLOSE, both sides:

1. Stop accepting frames in either direction.
2. Zeroize `K_s_AG`, `K_s_GA`, `IV_AG`, `IV_GA`, `prk`, `ss`, all replay
   bitmaps, both nonces, and the session-state slot.
3. Free the slot back to the pre-sized array.

A session that goes idle for 90 s with no traffic and no rekey is closed
with `reason = 0x03`, regardless of which side notices first. There is no
"keep-alive" — silence on the wire is the keep-alive of last resort.

---

## 10. Active denial — what happens when something is wrong

| Event | Operational response | Silent-monitoring response |
|---|---|---|
| Knock token mismatch | Drop. No reply. No log. | `bad_knock` counter ++ |
| Out-of-cone signal > -90 dBm | 60 s TX blackout | RF survey records bearing |
| 3 bad knocks in 60 s on one `id_A` | 600 s lockout for that aircraft | Page §6 silent IDS |
| Dilithium signature fail | Abort handshake | `sig_fail` counter ++ |
| Kyber decap fail (FO reject) | Abort handshake | `decap_fail` counter ++ |
| AEAD tag fail in session | Drop, strike +1 | `aead_fail` counter ++ |
| 3 AEAD strikes in 60 s | Tear down session, 600 s lockout | Page §6 silent IDS |
| HSM tamper | Zeroize everything | Page §6 + DR §10 |
| OTP fuse / runtime config disagree at boot | Refuse to start | Page §6 attestation alarm |
| Replay (seq already-seen) | Drop, strike +1 | `replay` counter ++ |
| Time skew > 3 s (in session) | Drop frame; if persistent for 5 frames, tear down | `clock_skew` event |

The asymmetry is by design. The operational plane gives the attacker
nothing — no error code, no "permission denied," no timing channel.
The silent plane records everything for off-site analysis.

---

## 11. Forward secrecy and post-compromise security

| Compromise | Effect on past traffic | Effect on future traffic |
|---|---|---|
| Long-term `sk_A` leaked | None. (`sk_A` only signs handshake; no session key derivation depends on it.) | Attacker can impersonate aircraft until the key is revoked. |
| Long-term `sk_G` leaked | None. | Attacker can impersonate ground until revoked. |
| `K_master[A]` leaked | None. (Knock is gating, not key material for AEAD.) | Attacker can knock until the key is rotated; still defeated by §1 directional check unless they're also in-cone. |
| One session key `K_s` leaked | Only that 30 s window of AEAD frames decryptable. Prior windows used different `K_s` and have been zeroized. | Next rekey replaces `K_s`. |
| `esk` leaked from RAM dump | Only relevant during the 1-frame window before zeroize; in practice zero. | None. |
| HSM seizure with valid power | Tamper switch zeroizes before extraction. | None. |

**Capture-and-decrypt-later** against Kyber-1024 + AES-256-GCM under a
30 s rekey is not a credible attack against any current or near-future
quantum adversary. The protocol's "long now" — the longest window over
which one key protects data — is 30 seconds.

---

## 12. Side-channel discipline

- All Kyber decapsulation, Dilithium verification, HMAC compare, and
  GCM tag compare are **constant-time** with respect to secret data.
- AES-NI / ARMv8 Crypto Ext provides constant-time AES.
- The Kyber implementation MUST be a known constant-time reference
  (e.g., `pqcrystals-kyber` reference + `_avx2` variant on x86, or the
  `mlkem-rust` audited port). No data-dependent branches on `ss`.
- HKDF, HMAC, and SHA3 implementations MUST be constant-time over secret
  inputs.
- The frame decoder MUST NOT short-circuit on the first byte mismatch
  in any secret-comparing field.
- Power-line and EM emissions are filtered (architecture §1, §6).
- The transponder C build forbids variable-time integer ops over secret
  data; `secret_t` types are wrapped to compile-error on `==`/`<`/`>`
  against secret operands.

---

## 13. Failure modes and engineering considerations

This section is for the implementers. None of these affect security; all
affect availability or operability.

- **Clock**: The 3 s in-session window assumes both sides have GPS-disciplined
  clocks. Aircraft INS plus periodic GPS gives ≪ 100 ms. Ground GPS plus
  rubidium holdover gives ≪ 10 ms over 24 h. A 3 s window is generous.
- **Boot timing**: A ground station boots in < 8 s from cold. During boot
  the radio is RF-muted; aircraft re-knock until Phase 0 is reached.
- **Aircraft transmitter cut**: If steering error > 1° (architecture §8),
  the aircraft drops to listen-only. The ground sees a session timeout
  and tears down at 90 s. The aircraft re-knocks once steering is back.
- **Link saturation**: A Phase-5 frame is ~1280 bytes max. At 5 ms RTT
  on directional UHF, sustained throughput is well above what ATC voice
  + data link requires.
- **Rekey collision**: If both sides initiate rekey within the same 200 ms
  window, the side with the lower `id_G || id_A` lexicographic prefix
  wins; the other aborts its rekey offer and processes the peer's.

---

## 14. What this protocol does NOT do

For the avoidance of doubt:

- It does not multiplex many aircraft on one session. One aircraft, one
  session.
- It does not negotiate cipher suites. The cipher suite is fuse-locked
  (architecture §2). A peer offering a different suite is hostile and is
  dropped.
- It does not retry across reboots. Boot wipes session state.
- It does not federate. Each ground station has independent enrolment and
  trust roots; cross-site trust lives only in the offline enrolment
  process.
- It does not acknowledge unauthenticated traffic. The "denial" frame in
  some protocols is itself an oracle; we do not have one.

---

## 15. Test vectors and conformance

Conformance tests live in `ground-station/tests/` and `transponder/tests/`.
They include:

- KAT vectors for Kyber-1024 KEM (NIST PQC reference).
- KAT vectors for Dilithium-5 (NIST PQC reference).
- A complete handshake with fixed nonces and a fixed clock, producing a
  stable byte-for-byte session-key set.
- Negative tests: bad knock, bad sig, bad decap, replay, clock skew,
  cone violation. Each MUST result in zero observable response on the
  operational plane and exactly one event on the silent plane.

A conformant implementation passes all KATs and all negative tests.

---

## Appendix A · Wire-format constants

```
VER_V1            = 0x01
MSG_KNOCK         = 0x01    (knock_token implicit; see §3 layout)
MSG_KEM_OFFER     = 0x10
MSG_KEM_RESP      = 0x11
MSG_DATA          = 0x20
MSG_REKEY_OFFER   = 0x30
MSG_REKEY_RESP    = 0x31
MSG_CLOSE         = 0x40

WINDOW_KNOCK_S    = 30
WINDOW_HANDSHAKE_TIME_S = 5
WINDOW_SESSION_TIME_S   = 3
SESSION_REKEY_S   = 30
SESSION_IDLE_TIMEOUT_S  = 90
LOCKOUT_AFTER_STRIKES   = 3
LOCKOUT_WINDOW_S        = 60
LOCKOUT_HOLD_S          = 600
REPLAY_WINDOW_FRAMES    = 256
```

Any deviation from these constants — at runtime — is a fuse-policy
violation (architecture §2) and the security processor refuses to start.
