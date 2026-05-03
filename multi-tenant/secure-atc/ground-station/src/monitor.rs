//! Silent telemetry events emitted by the operational plane.
//!
//! In production, events flow through the one-way optical isolator
//! described in [`03-monitoring.md`](../../docs/03-monitoring.md). The
//! sink here is a simple trait so the daemon can route events to a
//! pipe (real diode), a counter (tests), or stderr (developer mode).
//!
//! By design these events go OUT only. There is no return path for the
//! monitoring plane to influence the operational plane.

use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};

/// All event variants emitted by the operational ground-station code.
///
/// Severities are documented next to each variant. The SIEM applies
/// routing rules per [`03-monitoring.md`](../../docs/03-monitoring.md) §4.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MonitorEvent {
    /// Knock-token verification failed. **Medium** severity individually;
    /// repeated bad knocks for the same `id_a` escalate to **high**.
    BadKnock {
        /// Aircraft id from the frame (may be unenrolled).
        id_a: u64,
        /// Short reason string, e.g. `"parse"`, `"token"`, `"wrong-id"`.
        reason: &'static str,
        /// Wall-clock seconds.
        t: u64,
    },
    /// A knock arrived for an aircraft that is currently in lockout.
    /// **Medium** — usually a clock-skew aircraft retrying.
    LockedOutKnock {
        /// Aircraft id.
        id_a: u64,
        /// Wall-clock seconds.
        t: u64,
    },
    /// A handshake step failed (Phase 2 or Phase 3). **High** because
    /// signature/decap failures should never happen by accident.
    BadHandshake {
        /// Aircraft id.
        id_a: u64,
        /// Failure reason short string.
        reason: &'static str,
        /// Wall-clock seconds.
        t: u64,
    },
    /// A session was successfully established.
    SessionEstablished {
        /// Aircraft id.
        id_a: u64,
        /// Wall-clock seconds.
        t: u64,
    },
    /// A 30-second rekey completed.
    RekeyComplete {
        /// Aircraft id.
        id_a: u64,
        /// Wall-clock seconds.
        t: u64,
    },
    /// AEAD authentication failed in-session. **High** — never normal.
    AeadFailure {
        /// Aircraft id.
        id_a: u64,
        /// Sequence number on which the failure happened.
        seq: u64,
        /// Wall-clock seconds.
        t: u64,
    },
    /// Replay window rejected a frame. **High**.
    Replay {
        /// Aircraft id.
        id_a: u64,
        /// Sequence number that was already-seen or out-of-window.
        seq: u64,
        /// Wall-clock seconds.
        t: u64,
    },
    /// Per-aircraft strike count tripped lockout. **High**.
    Lockout {
        /// Aircraft id.
        id_a: u64,
        /// Wall-clock seconds.
        t: u64,
    },
    /// Clock skew between peer and local frame seen.
    ClockSkew {
        /// Aircraft id.
        id_a: u64,
        /// Skew in seconds (peer minus local).
        offset_s: i64,
        /// Wall-clock seconds.
        t: u64,
    },
    /// Daemon heartbeat — emitted at 1 Hz so the silent IDS can detect
    /// silence (spec §3.9 of monitoring doc).
    Heartbeat {
        /// Boot-relative counter.
        counter: u64,
        /// Wall-clock seconds.
        t: u64,
    },
    /// Boot-time attestation summary.
    BootAttestation {
        /// 32-byte SHA3-256 digest of the boot measurement.
        measurement: [u8; 32],
        /// Wall-clock seconds.
        t: u64,
    },
}

impl fmt::Display for MonitorEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BadKnock { id_a, reason, t } => {
                write!(f, "[t={t}] bad_knock id_a={id_a:#018x} reason={reason}")
            }
            Self::LockedOutKnock { id_a, t } => {
                write!(f, "[t={t}] locked_out_knock id_a={id_a:#018x}")
            }
            Self::BadHandshake { id_a, reason, t } => {
                write!(f, "[t={t}] bad_handshake id_a={id_a:#018x} reason={reason}")
            }
            Self::SessionEstablished { id_a, t } => {
                write!(f, "[t={t}] session_established id_a={id_a:#018x}")
            }
            Self::RekeyComplete { id_a, t } => {
                write!(f, "[t={t}] rekey_complete id_a={id_a:#018x}")
            }
            Self::AeadFailure { id_a, seq, t } => {
                write!(f, "[t={t}] aead_fail id_a={id_a:#018x} seq={seq}")
            }
            Self::Replay { id_a, seq, t } => {
                write!(f, "[t={t}] replay id_a={id_a:#018x} seq={seq}")
            }
            Self::Lockout { id_a, t } => write!(f, "[t={t}] lockout id_a={id_a:#018x}"),
            Self::ClockSkew { id_a, offset_s, t } => {
                write!(f, "[t={t}] clock_skew id_a={id_a:#018x} offset_s={offset_s}")
            }
            Self::Heartbeat { counter, t } => write!(f, "[t={t}] heartbeat n={counter}"),
            Self::BootAttestation { measurement, t } => {
                write!(f, "[t={t}] boot_attestation measurement={}", hex32(measurement))
            }
        }
    }
}

fn hex32(b: &[u8; 32]) -> String {
    let mut s = String::with_capacity(64);
    for byte in b {
        use std::fmt::Write;
        let _ = write!(s, "{byte:02x}");
    }
    s
}

/// Sink for monitor events.
pub trait MonitorSink {
    /// Record one event. Returning is best-effort — the diode hardware
    /// in production cannot fail-stop the operational plane.
    fn record(&mut self, event: MonitorEvent);
}

/// A counting sink — used by tests.
#[derive(Default, Debug)]
pub struct CountingMonitor {
    /// Total events recorded since construction.
    pub count: AtomicU64,
    /// Last 32 events; older are evicted.
    pub recent: Vec<MonitorEvent>,
}

impl MonitorSink for CountingMonitor {
    fn record(&mut self, event: MonitorEvent) {
        self.count.fetch_add(1, Ordering::Relaxed);
        self.recent.push(event);
        if self.recent.len() > 32 {
            self.recent.remove(0);
        }
    }
}

/// Stderr sink — used by the developer-mode binary.
#[derive(Default, Debug)]
pub struct StderrMonitor;

impl MonitorSink for StderrMonitor {
    fn record(&mut self, event: MonitorEvent) {
        eprintln!("monitor: {event}");
    }
}

/// Discarding sink — used when telemetry has nowhere to go.
#[derive(Default, Debug)]
pub struct NullMonitor;

impl MonitorSink for NullMonitor {
    fn record(&mut self, _event: MonitorEvent) {}
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counting_monitor_accumulates() {
        let mut m = CountingMonitor::default();
        m.record(MonitorEvent::Heartbeat { counter: 1, t: 100 });
        m.record(MonitorEvent::Heartbeat { counter: 2, t: 101 });
        assert_eq!(m.count.load(Ordering::Relaxed), 2);
    }
}
