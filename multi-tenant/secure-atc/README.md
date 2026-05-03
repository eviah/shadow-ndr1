# SHADOW-ATC · Impenetrable ATC Communications

A clean-room design + reference implementation for an aircraft↔ATC communication
system whose core security property is **invisibility before invincibility**:
unauthorized observers cannot identify that the channel exists, let alone reach it.

## What this directory contains

| Path | What it is | Status |
|---|---|---|
| `docs/00-architecture.md` | End-to-end blueprint: physical, logical, crypto, human layers + threat model | spec |
| `docs/01-crypto-protocol.md` | SHADOW-COMM v1 protocol spec (knock, PQ-KEM, session, rekey, denial) | spec |
| `docs/02-hsm-config.md` | Hardware root-of-trust, key custody, two-person rule | spec |
| `docs/03-monitoring.md` | Silent intrusion-detection sensors that don't reveal the channel | spec |
| `docs/04-disaster-recovery.md` | Physical compromise playbook (no remote backdoors) | spec |
| `ground-station/` | Rust reference implementation (Kyber-1024, Dilithium-5, AES-256-GCM, FSM) | runs |
| `transponder/` | Embedded-C skeleton for the aircraft side | builds in POSIX mode |

## What's real vs. specified

A system this ambitious is two-thirds *operational* — beamforming antennas,
buried fiber, Faraday-caged buildings, hardware-fused security policies, sealed
HSMs, two-person rules, biometric vaults. None of that ships in a git
repository. The docs spell out those controls explicitly so deployment teams
know what's required to actually achieve the security property.

What this repository **does** ship:

- A protocol design that the security property hangs on (silence-before-handshake,
  PQ-KEM, 30 s forward-secret rekey, replay windows, lockout state machine)
- A Rust ground-station daemon implementing that protocol against real PQ libs
- An embedded-C reference for the transponder that mirrors the same FSM
- Silent IDS hooks that tell you about probe attempts without changing the
  channel's observable behaviour

Read `docs/00-architecture.md` first.
