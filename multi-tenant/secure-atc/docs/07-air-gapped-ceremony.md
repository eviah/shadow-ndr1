# SHADOW-ATC — Air-Gapped Key Ceremony (frontier upgrade #21)

## 1. Scope

This SOP governs generation of every long-term key in the SHADOW-ATC
trust hierarchy:

| Key                                | Algorithm           | Quantity      |
| ---------------------------------- | ------------------- | ------------- |
| Ground long-term signing key       | ML-DSA-87           | 1 per site    |
| Ground long-term signing key (XMSS)| XMSS^MT-SHA3-256/H20| 1 per site    |
| Ground long-term signing key (SLH) | SPHINCS+-SHAKE-256s | 1 per site    |
| Aircraft per-tail signing key      | ML-DSA-87           | 1 per tail    |
| Aircraft `k_master`                | 256-bit symmetric   | 1 per tail    |

Threshold ML-DSA shares (frontier #4) are produced inside the ceremony
room as part of the ground-key generation; no key ever exists in
single-share form outside the air gap.

## 2. Physical environment

- **Two rooms.** *Anteroom* (Faraday rated ≥ 60 dB, mantrap, no
  electronics) and *ceremony room* (Faraday rated ≥ 100 dB, no power
  outlets connected to the building grid — battery only, no windows,
  no telecom drops).
- **Bug sweep** by an outside security firm immediately before each
  ceremony, recorded on tape held in the safe of an offsite custodian.
- **No personal items** past the anteroom: phones, watches, jewelry,
  hearing aids with wireless capability, glasses with electronic
  components, prosthetics with telemetry. Body cavity check is a hard
  requirement for SO-class ceremonies.
- **Three-camera recording** with audio. Tapes ride out in the SO's
  custody; copies are sealed and held for 25 years.

## 3. Personnel

| Role           | Min  | Notes                                                          |
| -------------- | ---- | -------------------------------------------------------------- |
| Security Officer (SO) | 1 | Holds the OTP fuse-burn key. May not also be a custodian.   |
| Operator A     | 1    | First operator on dual-control gates.                          |
| Operator B     | 1    | Second operator. May not be from the same employer as Op A.    |
| Witness        | 1    | External party (regulator, third-party auditor).               |
| Custodians     | 3..5 | Off-duty during the ceremony; arrive at the end to receive shares. |

No single person, including the SO, may at any time be alone with the
ceremony hardware in a powered state.

## 4. Entropy sources (combined, not single-sourced)

The 256-bit master entropy seed is `SHA3-512` of:

1. **QRNG.** ID Quantique Quantis QRNG-PCIe-240M, 256 bytes captured
   at 240 Mbit/s with health-test pass.
2. **Radioactive decay.** A sealed Cs-137 source + Geiger counter
   feeds 256 bytes of inter-event-time samples LSB-extracted.
3. **Operator dice.** Two operators each roll 50 D20 rolls — recorded
   on camera, transcribed in the ceremony room, hashed in.
4. **Atmospheric noise.** 256 bytes from a calibrated VHF white-noise
   receiver inside the cage (SDR with antenna terminated through a
   precision 50 Ω load + LNA + ADC).
5. **System TRNG.** Whatever the HSM's certified TRNG produces.

The seed is fed into the HSM's KDF only inside the ceremony hardware.
No source is trusted alone; the seed is `SHA3-512(s1 ‖ s2 ‖ s3 ‖ s4 ‖
s5)`.

## 5. Procedure (single-tail aircraft enrolment)

### Step 1 — Power on

The SO unlocks the ceremony rack with key #1 (held in the SO's safe).
Operator A unlocks key #2 (held in the airline's vault). Without
**both** keys the rack cannot draw power. The HSM boots from its OTP
fuse map (see [02-hsm-config.md](02-hsm-config.md)) into ceremony mode.

### Step 2 — Health checks

The HSM runs:
- `pst_kat` — known-answer tests for AES, SHA3, ML-KEM, ML-DSA.
- `tamper_self_test` — verifies the active mesh and capacitor backup.
- `entropy_health` — NIST SP 800-90B CT and APT tests on the in-band
  TRNG.

Any failure halts the ceremony. The operators MUST NOT bypass.

### Step 3 — Entropy capture

Each entropy source is captured in turn, on camera. Outputs are
displayed on the ceremony console as hex; operators visually verify
that no source is producing all-zeros or a stuck pattern. The seed
is hashed inside the HSM; the unhashed bytes are wiped from the
ceremony console RAM before step 4.

### Step 4 — Key generation

The HSM derives:
- `k_master[A]` (32 bytes, never leaves the HSM in plaintext)
- `pk_a, sk_a` (ML-DSA-87 keypair). `sk_a` is split into 5 Shamir
  shares with threshold 3.

`k_master[A]` is also Shamir-split (3-of-5) using the byte-wise GF(2^8)
construction in [`rpss.rs`](../ground-station/src/rpss.rs).

### Step 5 — Token engraving

The 5 Shamir shares are written to 5 hardware tokens:
- USB-C with an integrated secure element (e.g. **YubiHSM 2** with
  PIV / PKCS#11 wrapper, or **SoloKey 2** with FIDO2 storage).
- Each token is initialised with a custodian-chosen PIN inside the
  ceremony room (custodians enter on a keypad shielded against
  acoustic side-channel — silicone-dampened keys).

A label is laser-engraved onto each token: `SHADOW-ATC / TAIL-{id_a} /
SHARE {n}/5 / EPOCH 0 / {YYYY-MM-DD}`.

### Step 6 — Custodian dispatch

After the ceremony, custodians physically separate. No two share-tokens
may ever travel together. Recommended custody plan (3-of-5 threshold):

| Share | Custodian        | Storage location               |
| ----- | ---------------- | ------------------------------ |
| 1     | Site SO           | Site safe, dual-key            |
| 2     | Regulator escrow  | Civil aviation authority vault |
| 3     | Operator B's HQ   | Bank deposit box               |
| 4     | Off-site replica  | Disaster-recovery bunker       |
| 5     | Independent auditor | Third-country jurisdiction   |

## 6. Aircraft enrolment installation

`k_master[A]` arrives at the avionics OEM as a 5-share package. The
OEM's HSM, attended by 2 of the 5 custodians + Operator A from this
ceremony, reconstructs the master inside its tamper-respondent boundary
and burns it into the aircraft transponder's secure element. The
shares used are wiped on the OEM's HSM after burn; the 5-share record
remains intact at the ground side.

## 7. Periodic re-randomization

Per frontier #12 (RPSS), the in-storage shares are re-randomized on
hourly cadence by the HSM cluster. Hardware tokens hold *epoch-0*
shares as a cold-storage backup for unrecoverable site-loss; recovery
from epoch-0 requires re-enrolment of the aircraft (the live shares
have been refreshed many times since).

## 8. Drill cadence

- **Quarterly** ceremony rehearsal at every site (no real keys; uses
  test seeds). Stale > 90 days = no ceremony permission for that team.
- **Annual** key rollover. Old keys are wiped on tokens via factory
  reset on camera; the rotation is logged in the audit chain
  ([22](05-frontier-upgrades.md#22-end-to-end-merkle-audit-trail)).

## 9. Failure modes — what to do

| Symptom                              | Action                                |
| ------------------------------------ | ------------------------------------- |
| HSM entropy health-test fails        | Abort. Replace HSM. Repeat ceremony.  |
| Camera tape jams                     | Abort. Photograph state + reschedule. |
| Operator suspects coercion           | Operator silently invokes duress codeword on keypad. SO halts ceremony. (See [04-disaster-recovery.md](04-disaster-recovery.md) DR-7.) |
| Power glitch detected                | Abort. Verify capacitor zeroize fired. |
| Witness disputes a step              | Abort. Re-run from step 1 next day.   |
