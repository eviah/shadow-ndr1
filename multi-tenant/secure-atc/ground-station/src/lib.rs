//! SHADOW-ATC · ground-station reference library
//!
//! Implements the SHADOW-COMM v1 protocol on the ground side. The
//! division into modules mirrors the spec under `../docs/`:
//!
//! * [`protocol`]  — wire-format constants and frame types (spec §A).
//! * [`crypto`]    — AES-256-GCM, HKDF-SHA3-512, HMAC-SHA3-256 wrappers.
//! * [`knock`]     — Phase-1 knock token, per-aircraft strike state.
//! * [`session`]   — state machine for one aircraft session.
//! * [`rekey`]     — 30-second forward-secret rekey loop.
//! * [`hsm`]       — opaque-handle interface to the hardware HSM.
//! * [`monitor`]   — one-way telemetry events to the silent IDS plane.
//!
//! Frontier upgrades (see `../docs/05-frontier-upgrades.md`):
//!
//! * [`qkd`]        — hybrid PQ + QKD salt injection (#1)
//! * [`multisig`]   — triple-signature OFFER (#3)
//! * [`threshold`]  — n-of-m threshold ML-DSA signing (#4)
//! * [`vdf`]        — sequential-proof anti-replay (#9)
//! * [`rpss`]       — randomized proactive secret sharing (#12)
//! * [`qrng`]       — quantum RNG hook (#13)
//! * [`puf`]        — physically unclonable function hook (#15)
//! * [`keytree`]    — forward-secret ephemeral key tree (#18)
//! * [`audit`]      — Merkle audit trail (#22)
//!
//! This crate is `#![forbid(unsafe_code)]`. The ground daemon binary in
//! `src/main.rs` ties the modules together.

#![forbid(unsafe_code)]
#![allow(missing_docs)]

pub mod audit;
pub mod crypto;
pub mod hsm;
pub mod keytree;
pub mod knock;
pub mod monitor;
pub mod multisig;
pub mod protocol;
pub mod puf;
pub mod qkd;
pub mod qrng;
pub mod rekey;
pub mod rpss;
pub mod session;
pub mod threshold;
pub mod vdf;

pub use protocol::{Frame, MsgType, PROTOCOL_VERSION};
pub use session::{Session, SessionError, SessionState};
