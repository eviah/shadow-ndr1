# SHADOW-ATC · Disaster Recovery Playbook

> *There are no remote backdoors to recover with. A breach means a
> physical key custodian flies to the affected site with sealed
> hardware. The plane is faster than the cleanup.*

This playbook covers what to do when something has gone wrong at a
ground station. By design there are no soft-recovery paths — the
system cannot be "logged into" remotely to fix. Every recovery is
hands-on-hardware.

---

## 1. Recovery principles

1. **No remote anything.** Recovery requires a physically present
   custodian. There is no SSH, no remote console, no SMS code, no
   "support tunnel." Anyone offering one is hostile.
2. **Two-person rule remains.** Even in an emergency, custody actions
   require two custodians. Three are dispatched per incident so that
   one is always available as a witness or relief.
3. **Sealed hardware.** Replacement HSMs, operator cards, and crypto
   dies travel in numbered tamper-evident bags with airline-tracked
   custody chains. Bag integrity is verified on arrival; a broken bag
   means the contents are scrap.
4. **No partial states.** Recovery either fully completes or rolls
   forward to a clean re-provision. Half-recovered sites do not
   serve traffic.
5. **The paper roll is truth.** When the digital record disagrees with
   the perforated thermal-printer roll (architecture §5), the paper
   wins. The roll is what regulators read.

---

## 2. Incident classification

| Class | Trigger | Severity | First response |
|---|---|---|---|
| **DR-1** Tamper | HSM tamper switch fired; OTP "tamper evidence" fuse burned | critical | Immediate site isolation; full hardware swap |
| **DR-2** Cage breach | Faraday attenuation < 80 dB *or* door interlock violated outside schedule | critical | Site isolation; on-site security dispatched |
| **DR-3** Fibre disturbance | OTDR delta or laser interlock break on a dark-fibre run | high | Operational fail-over to peer site; physical inspection |
| **DR-4** Attestation fail | Boot measurement disagreed with OTP reference, or daemon refused to start | critical | Hardware quarantine; root-cause investigation |
| **DR-5** Pattern of probes | Silent IDS sees coordinated probing across multiple `id_A` | high | No site action (silence is the response); raise sector alert |
| **DR-6** Insider event | Two-person rule attempted-bypass, badge clone, biometric mismatch | critical | Site isolation; operators relieved pending review |
| **DR-7** Power-line / EM injection | Power-current signature anomaly, EM differential coil triggered | high | Switch to UPS-isolated rail; physical inspection |
| **DR-8** Loss of ≥ 2 sensors | Monitoring plane goes blind on 2+ sensors simultaneously | high | Site is treated as compromised until restored (a blind monitor is a blind defence) |
| **DR-9** Region-wide outage | ≥ 2 ground stations in one region down | critical | Air-traffic procedural fallback (procedural separation, paper strips) until ≥ 1 site recovers |

Classification is automatic from the silent-monitoring event stream
(see `03-monitoring.md`); operators do not have the option to
*lower* a classification. They can only raise.

---

## 3. Immediate response (first 60 minutes)

### 3.1 Site isolation

For DR-1, DR-2, DR-4, DR-6, DR-8 (anything that suggests the site itself
may be compromised):

1. The on-call duty officer **at the SIEM (off-site)** sees the page.
2. They contact the airline operations centre and CAA liaison.
3. ATC traffic is **handed off** to peer ground stations in the region.
   Aircraft re-knock to the new ground station, the new session opens
   in < 50 ms, ATC continues without voice continuity loss.
4. The compromised site is **declared dark**. Aircraft are instructed
   over the still-operational peer sites that this site is offline.
5. The site daemon, observing 10 s of no incoming knocks plus a
   signed "go dark" message from the SIEM diode (the only signal the
   diode permits to the operational plane is this single bit, and even
   that is implemented as the *absence* of a heartbeat from the SIEM
   side, not as a positive command), enters quiescence and zeroizes
   session state.

The "go dark" mechanism deserves elaboration: the SIEM does not get a
return channel to the operational plane. What it has is a separate,
purely-passive **dead-man interlock**: the operational plane's daemon
listens for a 1 Hz integrity beacon on a *physically separate* fibre,
sourced by the silent-monitoring HSM. When the beacon stops, the
daemon assumes the worst and goes quiet. The duty officer triggers the
beacon stop (a physical button on the SIEM console) for an isolation
event. The asymmetry — heartbeat absence is the only signal — keeps
the operational plane from being driven by adversary-injected commands.

### 3.2 Custodian dispatch

Within 60 min of a DR-1, DR-2, DR-4, or DR-6 page:

- Three custodians are dispatched: two for the work, one as observer.
  Each carries a numbered card and a sealed hardware kit.
- They travel separately when possible. They re-converge at the site.
- Their badge cards are pre-issued for this single site visit; on
  arrival they are activated by a phone call to the duty officer and
  expire 24 h after arrival.

### 3.3 On-site arrival

1. Verify the building seal (a tamper-evident sticker placed on the
   outer door whenever the building is closed unattended). Broken seal
   → site is treated as physically penetrated; do not enter alone;
   call physical security.
2. Verify Faraday cage seal.
3. Verify HSM tamper switch state.
4. Verify the thermal-printer roll has not been removed; capture the
   most recent entries on photograph (chain of custody).
5. Verify the optical jukebox is intact and that the most recent disc
   matches the printer roll.
6. Power down the operational plane. Power down the monitoring plane
   *separately*, and only after capturing an attestation snapshot
   from it.

---

## 4. Hardware swap procedure

For DR-1 (HSM tamper) and DR-4 (attestation fail):

1. The HSM is physically removed and placed in a sealed evidence bag.
   It is never powered up again at this site. It is shipped to the
   manufacturer for forensic decap.
2. A replacement HSM (sealed, numbered, with paired enrolment under
   the airline's master enrolment HSM) is installed.
3. The replacement HSM is initialized at the factory with:
   - factory-burned OTP fuses (architecture §7),
   - the airline's master public key,
   - the regional `gs/longterm/sig.prev` (so it accepts existing
     enrolments during the rotation grace window).
4. On site, the replacement HSM is brought online by the two
   custodians performing a **k=2-of-N keyholder ceremony**:
   - Each holds one Shamir share of the regional rotation key.
   - The HSM combines the shares, derives the rotation key, signs
     a "site activation" message, and from that moment can sign for
     the site's `gs/longterm/sig`.
   - A new local `gs/longterm/sig` keypair is generated **inside the
     new HSM** and certified by the rotation key.
5. Aircraft enrolment objects (`enrol/{id_A}/pk` and
   `enrol/{id_A}/k_master`) are re-imported from the **airline-level
   enrolment HSM** via a one-shot wrapped channel. The original
   enrolments are not recoverable from the seized HSM (it zeroized);
   they are recoverable from the enrolment cage's master HSM.
6. Boot the replacement security processor; confirm attestation
   matches OTP fuses; confirm operational plane comes up.
7. Custodians sign a paper completion form; place the form in the
   thermal printer roll's continuation envelope; log to the
   monitoring plane's append-only event stream.

The site re-enters service only after the duty officer at the SIEM
**observes attestation** and confirms a clean handshake from a
test aircraft.

---

## 5. Cage breach procedure (DR-2)

A Faraday cage breach is treated as **possible RF emission leak**:

1. Site goes dark immediately.
2. RF survey from outside the building is performed by the silent
   monitoring plane's external sensors (architecture §6) for the
   preceding 24 h, looking for any operational-plane signal that
   leaked outside the cage during the breach.
3. If any leak is found, the **session keys for any active session
   during the breach window** are presumed compromised (they were
   already 30 s rekeyed many times, but defence in depth):
   - The operational HSM rotates `gs/longterm/sig`.
   - All in-flight aircraft are forced to re-knock.
4. The cage seal is repaired (physical contractor, escorted, full
   re-attenuation test ≥ 80 dB across 100 MHz – 18 GHz).
5. Site re-enters service.

If the cage breach correlates with active probing on the silent IDS
(DR-5 patterns observed *during* the cage breach), the site stays
dark for at least 7 days while a forensic team investigates.

---

## 6. Fibre disturbance (DR-3)

1. Operational plane fails over to peer sites (no aircraft impact;
   redundancy §11 of architecture covers this).
2. Physical inspection of the fibre run: walk the conduit, verify
   no surface tap, no spliced enclosure, no induction loop.
3. If a tap is found, the conduit is replaced end-to-end (not
   spliced), and the *suspect* segment is preserved as forensic
   evidence.
4. If no tap is found and the OTDR returns to baseline within 24 h,
   the disturbance is logged as benign (e.g., construction nearby,
   temperature shift) and the site re-enters service.
5. If OTDR remains anomalous, the run is replaced regardless. Dark
   fibre is cheap; certainty is not.

---

## 7. Insider event (DR-6)

| Sub-event | Response |
|---|---|
| Single failed biometric (operator's bad day) | Logged; no action |
| Repeated failed biometric on same operator | Operator referred for re-enrolment; cards revoked pending review |
| Two-person rule attempted bypass (one operator on two consoles, time-spliced) | Operator immediately removed from access; investigation; criminal referral if intent confirmed |
| Card clone detected (HSM observes card cert on a path that physically can't be the real card) | All cards in that operator's batch revoked; site re-enrols cards |
| Coercion duress code entered | Operator complies with attacker's surface request; HSM silently applies a duress policy: TX is suppressed, all session attempts fail with no error to the attacker, paper roll continues, monitoring plane pages security and dispatches response |

**Duress is treated as a normal operational state of "everything looks
fine to the attacker."** The attacker gets no signal that they have
been detected. Recovery is by external response, not by anything the
operator can visibly do.

---

## 8. Sensor blackout (DR-8)

If the monitoring plane loses ≥ 2 sensors simultaneously, the site is
**presumed compromised** until proven otherwise. Reasoning: an
adversary who can blind two sensors at once is well-resourced and
likely about to follow up with an attack.

Action:
1. Site goes dark.
2. Custodian dispatch as in §3.2.
3. Sensor outage is investigated physically. Common-cause failures
   (e.g., a single power-distribution unit feeding two sensors)
   are documented as architecture findings to be re-engineered.
4. Site does not re-enter service until all sensors are back to
   baseline AND the gap is explained.

---

## 9. Region-wide outage (DR-9)

If ≥ 2 of the 3 ground stations covering an ATC region are down:

1. ATC declares **procedural separation** for the affected airspace.
   Pilots fly published procedures with paper strips and HF voice as
   a fallback. (HF voice is not part of SHADOW-COMM and is not
   trusted for impenetrability — it's fallback, not primary.)
2. Aircraft are spaced wider, traffic flow is reduced, and en-route
   handoffs are coordinated by phone between adjacent regions.
3. The third (still-up) ground station continues to serve aircraft
   that are in its envelope, with degraded redundancy.
4. Recovery teams prioritize the closest down station; aim for one
   site back to service within 6 h (SLA).
5. Region returns to nominal once 2 of 3 sites are operational.

This is the condition that has the **biggest** safety implication, but
**no security implication** — there is no scenario where a region-wide
outage causes an information leak, only a capacity loss.

---

## 10. After-action

Within 7 days of any DR-1 through DR-7 event:

- Forensic report on the seized hardware (manufacturer decap, firmware
  diff, side-channel analysis if applicable).
- Root-cause analysis presented to the airline's CISO and the
  regulator.
- If the cause was an attack, an air-gap-aware **threat hunt** is
  performed across all regional sites to look for similar precursors
  in their own monitoring archives.
- If the cause was a vendor flaw, a fleet-wide field service
  bulletin is issued; all sites are scheduled for the corresponding
  hardware replacement under change control.
- If the cause was process (operator made a mistake), the procedure
  is updated and re-drilled. No blame; the procedure is the patch.

Retention: forensic reports are kept for the operational lifetime of
the system + 25 years. (Aircraft regulatory horizon.)

---

## 11. Drills

DR-1, DR-2, DR-3, DR-6, and DR-9 are drilled at least once per quarter
per site. The drill exercises:

- The dispatch chain (custodians actually fly out).
- The hardware swap (using a "drill HSM" that is physically identical
  but enrolled in a parallel airline namespace).
- The handoff to peer sites (real aircraft, real airspace, no
  passengers — drill flights or scheduled empty positioning legs).
- The paper trail (every drill produces a perforated thermal-printer
  envelope and an optical-jukebox entry).

A site that has not drilled in the last 90 days is **not allowed to
serve traffic**. The monitoring plane refuses to issue its 1 Hz
integrity beacon if drill records are stale; the operational plane
goes quiescent; aircraft route to peers.

This is severe by design. The whole-system property of this design is
"the recovery procedure works." If we don't know that, we don't ship.

---

## 12. What this DR procedure does NOT include

- It does not include a "remote unlock" tool. There is no such tool.
  Anyone calling the duty officer offering one is to be reported to
  CAA security.
- It does not include a "key escrow" recovery. Lost custodian shares
  are recovered by re-issuing fresh shares from the regional rotation
  HSM, not by reconstructing the original ones.
- It does not include an emergency cipher downgrade. The cipher suite
  is fuse-locked. There is no "let's try with a weaker key for an
  hour" path.
- It does not include a "we'll just trust this aircraft for now"
  bypass. Aircraft authenticate or they don't fly under SHADOW-COMM.
  Procedural separation is the fallback when authentication fails.
