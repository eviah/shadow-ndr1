# SHADOW-ATC · Silent Monitoring Plane

> *We watch them; they cannot watch us watching. Telemetry is one-way light.*

The monitoring plane exists to detect attack, error, drift, and tamper —
without giving the adversary any signal that it has been detected. Every
detection that pages a human is a detection the attacker did not see.

---

## 1. Architectural separation

The operational plane (the radio, fibre, ground-station daemon, HSM)
and the monitoring plane (sensors, IDS, SIEM forwarder) share **nothing
the operational plane writes through**:

- Distinct CPUs, distinct DRAM, distinct power rails.
- Distinct OS images, signed by distinct vendor keys.
- Sensors tap operational components passively. They never inject.

The two planes are connected by a single **optical isolator (data
diode)** — a literal LED → photodiode pair with no electrical path
backward. Telemetry flows from operational to monitoring (and from
monitoring to off-site SIEM) but never the reverse.

```
   ┌──────────────────────────┐         ┌────────────────────────────┐
   │   Operational plane      │ ──[D]── │   Monitoring plane         │
   │   (radio + fibre + HSM)  │         │   (sensors + IDS + SIEM)   │
   └──────────────────────────┘         └────────────────────────────┘
                                                       │
                                                  ──[D]── one-way to off-site NDR
```

`[D]` denotes a data diode. The diode is fail-stop: if the photodiode
side dies, telemetry stops; the operational plane is unaffected.

A consequence of this design: the monitoring plane cannot trigger any
defensive action on the operational plane. Defensive action is
*automatic* (architecture §1, lockouts) or *manual* via on-site
operator (architecture §5). The monitoring plane only **knows**.

---

## 2. Sensors

| # | Sensor | What it measures | Sample rate |
|---|---|---|---|
| S1 | RF spectrum survey | 100 MHz – 18 GHz I/Q snapshots, periodic | 1 Hz full sweep, 100 Hz on flagged bands |
| S2 | Out-of-cone receiver | RF energy from any direction outside the expected directional cone | continuous |
| S3 | Fibre OTDR | Optical-time-domain reflectometer on every fibre run | 1 reading / s |
| S4 | Loose-tube laser interlock | Laser bounce inside the conduit; any displacement breaks the beam | continuous |
| S5 | Power-line current signature | DC and AC current draw on every rail | 10 kHz |
| S6 | Knock decoder counters | Per-aircraft, per-direction: bad-knock, sig-fail, decap-fail, aead-fail, replay, clock-skew | every event |
| S7 | Cage door interlocks | Open/closed, latch torque | every transition |
| S8 | Vibration | Tri-axis MEMS at every cage corner and on every cabinet | 1 kHz |
| S9 | Thermal cameras | LWIR inside the cage, looking at people and equipment | 30 fps |
| S10 | EM injection detector | Differential coil pickup on power-line and fibre conduit | 100 kHz |
| S11 | Boot attestation | Per-boot measurement quote from the security processor | once / boot |
| S12 | HSM event stream | Every HSM operation (label, role, result), hash-chained | every event |
| S13 | Faraday cage integrity | Reference signal injected outside, measured inside; ratio = attenuation | 0.1 Hz |
| S14 | Clock health | GPS lock, rubidium holdover error, TAI offset agreement | 1 Hz |
| S15 | Daemon heartbeat | Operational ground-station daemon sends a counter every second | 1 Hz |

Sensor data is timestamped by a TAI-disciplined clock on the monitoring
plane (independent of the operational clock — disagreement between the
two is itself an event).

---

## 3. Detectors

Each detector consumes one or more sensor streams and emits **events**
(structured JSON Lines, one per finding). Detectors are stateless when
possible; stateful detectors check-point to the monitoring plane's
local store, never to the operational plane.

### 3.1 RF anomaly detector (S1, S2)

- Baseline: 30-day rolling spectral profile per band.
- Trigger: a power-density excursion > 3 σ for ≥ 5 s, or any signal
  in the cone-edge band.
- Output: `{type:"rf_anomaly", band, dbm, bearing, t_first, t_last}`

### 3.2 Optical disturbance detector (S3, S4)

- Trigger: OTDR delta > 0.1 dB at any fibre length, or interlock break.
- Output: `{type:"fibre_disturbance", run_id, dbm_delta, position_m}`
- Severity: high — fibre tamper is a precursor to most physical attacks
  on the dark-fibre layer.

### 3.3 Knock-failure pattern detector (S6)

Implemented as a **silent IDS**. Tracks per `id_A`:
- `bad_knocks_60s` — sliding count.
- `bad_sigs_session` — count within the same session attempt.
- `decap_fails_session` — same.
- `aead_fails_session` — same.
- `replay_count_session` — same.

Patterns to flag:

| Pattern | Severity | Plausible meaning |
|---|---|---|
| `bad_knocks_60s ≥ 3` | medium | Aircraft clock skew, or knock-token guess attempt |
| `bad_sigs ≥ 1`        | high   | Signature forgery attempt (Dilithium-5 sig should never randomly fail) |
| `decap_fails ≥ 1`     | high   | Either ciphertext bit-flip or active MITM attempt |
| `aead_fails ≥ 1`      | high   | In-session forgery attempt or key desync — never normal |
| `replay_count ≥ 1`    | high   | Replay attack |
| Multiple `id_A` with bad knocks within 60 s | critical | Coordinated probe across the fleet |

Output is emitted on the diode link with full context but is **not**
echoed on any RF or fibre interface.

### 3.4 Power-line / EM injection detector (S5, S10)

- Trigger: current-signature deviation correlated across ≥ 2 rails,
  *or* differential coil reading > 30 dB above noise floor.
- Output: `{type:"em_injection", coil, db_above_floor, t_window}`
- Severity: high. EM injection is a common physical-side-channel attack.

### 3.5 Site-physical detector (S7, S8, S9)

- Trigger: door open outside scheduled access window, vibration burst
  > threshold, thermal anomaly (e.g., person who isn't on the access
  schedule, equipment heating outside normal envelope).
- Output: `{type:"site_anomaly", subtype, sensor, score}`
- Severity: high to critical depending on subtype.

### 3.6 Faraday-cage integrity detector (S13)

- Trigger: attenuation drops below 80 dB on any band.
- Output: `{type:"cage_attenuation_low", band, db_now, db_baseline}`
- Severity: critical — the cage is a load-bearing assumption (architecture §1).

### 3.7 Clock-disagreement detector (S14)

- Trigger: monitoring-plane clock and operational-plane clock disagree
  by > 200 ms after holdover, OR GPS lock lost on either side for
  > 60 s without rubidium covering it.
- Output: `{type:"clock_drift", offset_ms, source_loss}`
- Severity: medium.

### 3.8 Boot-attestation detector (S11)

- Trigger: any boot whose measurement quote disagrees with the OTP
  reference, or whose firmware signature chain fails to verify.
- Output: `{type:"attestation_fail", measurement_actual, measurement_expected}`
- Severity: critical. The system is supposed to refuse to start in
  this case (architecture §7); the detector is a belt-and-braces.

### 3.9 Heartbeat-loss detector (S15)

- Trigger: no daemon heartbeat for 5 s.
- Output: `{type:"daemon_silent", last_heartbeat, gap_s}`
- Severity: high. Could be benign (planned restart) or could be a
  zeroize event.

---

## 4. Event severity and routing

The monitoring plane emits events to the off-site NDR SIEM (the same
SHADOW-NDR core that handles the broader fleet) over a second data
diode. The SIEM applies routing rules:

| Severity | Routing |
|---|---|
| `critical` | Immediate page to on-call security + airline duty officer + CAA liaison |
| `high`     | Page on-call security; ticket auto-created |
| `medium`   | Ticket auto-created; reviewed at next shift change |
| `low`      | Logged for trend analysis |

The diode link from the monitoring plane to the SIEM is itself
**signed** with `monitor/diode/key` (see HSM §1.2) so the SIEM can
detect tampering on the receiving side.

The SIEM cannot send anything back. Acknowledgements, suppressions,
and tunings are all applied on the SIEM side, downstream of the diode.

---

## 5. Detection that does not change observable behaviour

A core requirement: **detection must not change what the attacker
observes**. The monitoring plane:

- never emits RF,
- never sends a packet on the operational fibre,
- never causes the operational daemon to take a different action,
- never logs to the operational plane.

If a detector decides "this is bad," nothing visible changes on the
operational side. The aircraft handshake either proceeds (because the
attacker's frames failed cryptographically in the operational plane,
which always happens) or fails (because lockout triggered in the
operational plane, which always triggers on the same per-aircraft
strike rules — the attacker can't tell whether the lockout is
"because we caught you" or "because the strike count tripped").

The result: an attacker probing the system gets exactly the same
non-response whether or not their probes were noticed. They cannot
**learn** that we have detection.

---

## 6. Storage

Local to the monitoring plane:

- 30-day rolling I/Q recordings on bands of interest (compressed,
  encrypted with a key held only on the monitoring HSM partition).
- 365-day rolling event log, hash-chained.
- 7-day rolling thermal-camera footage.
- Continuous OTDR traces.

Remote (after the diode):

- All events, retained per CAA / regulator policy (typically 7 years).
- Aggregated summaries; raw I/Q is not exfiltrated by default — the
  bandwidth budget across the diode is sized for events, not bulk audio.

---

## 7. Why a one-way diode and not just a firewall

A firewall, however well-configured, is software. Software can be
wrong. A failure of the firewall could allow inbound packets that
modify the operational plane's behaviour or that exfiltrate keys.

A literal optical isolator — LED on the operational side, photodiode
on the monitoring side, with no electrical or optical return path —
is wrong only if the laws of physics are wrong. The operational plane
**physically cannot receive bytes** from the monitoring plane. A
compromise of the monitoring plane therefore cannot become a
compromise of the operational plane.

This is the same trade-off seen in nuclear reactor I&C: defensive
information flows out, never in.

---

## 8. What the monitoring plane does NOT do

- It does not authenticate aircraft. The operational plane does that.
- It does not decrypt operational traffic. It cannot — it does not
  hold the session keys, and the session keys never leave the HSM.
- It does not provide a remote-management surface. There is no SSH,
  no API, no web console reachable from outside the cage.
- It does not run untrusted code. Detector modules are vendor-signed
  and measured into the monitoring HSM partition at boot, just like
  the operational daemon.
- It does not page the **attacker**. (This is a joke, but it's the
  shape of the constraint: any output channel that the attacker can
  observe is, by construction, not on the monitoring plane.)
