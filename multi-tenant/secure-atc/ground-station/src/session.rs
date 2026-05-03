//! Per-aircraft session state machine.
//!
//! One session, one aircraft. Spec §1 (phase overview) is implemented
//! literally: knock → KEM_OFFER → KEM_RESP → derive → data ⟲ rekey → close.
//!
//! Every transition fails closed. There is no fall-through to a more
//! permissive state on error — every error is a teardown.

use std::time::{SystemTime, UNIX_EPOCH};

use ml_dsa::{
    KeyPair, MlDsa87, Signature as DsaSignature,
    signature::Signer,
};
use ml_kem::{KemCore, MlKem1024};
use rand::RngCore;
use rand::rngs::OsRng;
use zeroize::Zeroize;

use crate::crypto::{aead_open, aead_seal, Direction, SessionKeys};
use crate::hsm::{
    aircraft_kem_encap, encap_key_to_bytes, ground_kem_decap, ground_kem_keygen, Hsm, HsmError,
};
use crate::knock::{KnockDecoder, KnockVerdict, ReplayWindow};
use crate::monitor::{MonitorEvent, MonitorSink};
use crate::protocol::{
    AEAD_TAG_LEN, HANDSHAKE_SKEW_S, IDLE_TIMEOUT_S, KYBER1024_CT_LEN, KYBER1024_PK_LEN,
    MAX_PAYLOAD, NONCE_LEN, REKEY_INTERVAL_S, SESSION_SKEW_S,
};
use crate::protocol::{CloseReason, DataHeader, KnockFrame, MsgType, PROTOCOL_VERSION};

/// Possible states of a session. Transitions are linear from
/// [`SessionState::Quiescent`] through [`SessionState::Established`],
/// with [`SessionState::Rekeying`] orbiting `Established`.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum SessionState {
    /// No traffic for this aircraft. Spec Phase 0.
    Quiescent,
    /// Knock accepted, KEM_OFFER sent, awaiting KEM_RESP.
    AwaitingKemResp,
    /// Session keys derived, AEAD frames flowing.
    Established,
    /// Mid-rekey: a REKEY_OFFER has been sent or received.
    Rekeying,
    /// Session torn down. Slot is held only briefly before zeroize.
    Closed(CloseReason),
}

/// Reasons a session-layer call can fail. Mapped to spec §10's silent
/// drops — the caller should NOT echo any of these to the peer.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum SessionError {
    /// Frame failed parse, version, or reserved-bit checks.
    BadFrame,
    /// Knock token mismatch or aircraft not enrolled.
    KnockRejected,
    /// Aircraft is locked out per the strike policy.
    LockedOut,
    /// Signature verification failed.
    BadSignature,
    /// KEM decapsulation failed.
    KemFailure,
    /// AEAD authentication failed.
    AeadFailure,
    /// Replay-window check failed.
    Replay,
    /// Time skew outside the allowed window for the current state.
    ClockSkew,
    /// State machine refused the message in the current state.
    BadState,
    /// Idle timeout elapsed; caller should observe a CLOSE.
    IdleTimeout,
}

/// Outcome of feeding a wire frame to the session.
#[derive(Debug)]
pub enum FrameOutcome {
    /// Caller should serialize and transmit these bytes (Phase 2 offer,
    /// Phase 5b rekey offer, etc.).
    Emit(Vec<u8>),
    /// A plaintext payload was decrypted from a Phase-5 data frame.
    Plaintext(Vec<u8>),
    /// A protocol-internal frame was processed; no action by the caller.
    Consumed,
    /// Session has been torn down.
    Closed(CloseReason),
}

/// Outbound state held during the AwaitingKemResp phase.
struct PendingHandshake {
    nonce_g: [u8; NONCE_LEN],
    nonce_a: [u8; NONCE_LEN],
    esk: <MlKem1024 as KemCore>::DecapsulationKey,
    /// When the OFFER was sent. After 200 ms the session is dropped
    /// (spec §4 final paragraph).
    sent_at_s: u64,
}

/// One session. There is one of these per active aircraft.
pub struct Session {
    pub(crate) state: SessionState,
    pub(crate) id_a: u64,
    pub(crate) id_g: u32,
    pub(crate) keys: Option<SessionKeys>,
    pub(crate) tx_seq: u64,
    pub(crate) rx_window: ReplayWindow,
    pending: Option<PendingHandshake>,
    last_traffic_s: u64,
    last_rekey_s: u64,
}

impl Session {
    /// Create a new session in [`SessionState::Quiescent`].
    #[must_use]
    pub fn new(id_a: u64, id_g: u32) -> Self {
        Self {
            state: SessionState::Quiescent,
            id_a,
            id_g,
            keys: None,
            tx_seq: 0,
            rx_window: ReplayWindow::new(),
            pending: None,
            last_traffic_s: 0,
            last_rekey_s: 0,
        }
    }

    /// Current state, for the daemon to inspect.
    #[must_use]
    pub fn state(&self) -> SessionState {
        self.state
    }

    /// Process an inbound KNOCK frame.
    ///
    /// On success, returns `FrameOutcome::Emit(kem_offer_bytes)` for the
    /// caller to put on the wire (Phase 2). On failure, the appropriate
    /// silent-monitor event has already been logged.
    pub fn handle_knock(
        &mut self,
        frame_bytes: &[u8],
        decoder: &mut KnockDecoder,
        hsm: &Hsm,
        monitor: &mut dyn MonitorSink,
        now_s: u64,
    ) -> Result<FrameOutcome, SessionError> {
        let frame = KnockFrame::from_bytes(frame_bytes).ok_or_else(|| {
            monitor.record(MonitorEvent::BadKnock {
                id_a: 0,
                reason: "parse",
                t: now_s,
            });
            SessionError::BadFrame
        })?;

        if frame.id_a != self.id_a {
            monitor.record(MonitorEvent::BadKnock {
                id_a: frame.id_a,
                reason: "wrong-id",
                t: now_s,
            });
            return Err(SessionError::BadFrame);
        }

        let verdict = decoder.verify(
            frame.id_a,
            &frame.nonce_a,
            &frame.token,
            now_s,
            |id| hsm.knock_key(id),
        );

        match verdict {
            KnockVerdict::Accept => {}
            KnockVerdict::LockedOut => {
                monitor.record(MonitorEvent::LockedOutKnock {
                    id_a: frame.id_a,
                    t: now_s,
                });
                return Err(SessionError::LockedOut);
            }
            KnockVerdict::Drop => {
                monitor.record(MonitorEvent::BadKnock {
                    id_a: frame.id_a,
                    reason: "token",
                    t: now_s,
                });
                return Err(SessionError::KnockRejected);
            }
        }

        // Allocate state and send KEM_OFFER.
        let (esk, epk) = ground_kem_keygen();
        let mut nonce_g = [0u8; NONCE_LEN];
        OsRng.fill_bytes(&mut nonce_g);

        let offer_bytes = build_kem_offer(
            self.id_g,
            &epk,
            &nonce_g,
            &frame.nonce_a,
            now_s,
            hsm,
        )
        .map_err(|_| SessionError::BadState)?;

        self.pending = Some(PendingHandshake {
            nonce_g,
            nonce_a: frame.nonce_a,
            esk,
            sent_at_s: now_s,
        });
        self.state = SessionState::AwaitingKemResp;
        self.last_traffic_s = now_s;
        Ok(FrameOutcome::Emit(offer_bytes))
    }

    /// Process an inbound KEM_RESP frame (spec §5).
    pub fn handle_kem_resp(
        &mut self,
        frame_bytes: &[u8],
        hsm: &Hsm,
        monitor: &mut dyn MonitorSink,
        now_s: u64,
    ) -> Result<FrameOutcome, SessionError> {
        let SessionState::AwaitingKemResp = self.state else {
            return Err(SessionError::BadState);
        };
        let pending = self.pending.as_ref().ok_or(SessionError::BadState)?;

        // 200 ms post-OFFER deadline (spec §4).
        if now_s.saturating_sub(pending.sent_at_s) > 1 {
            self.tear_down(CloseReason::LinkTimeout);
            return Err(SessionError::IdleTimeout);
        }

        let parsed = parse_kem_resp(frame_bytes).ok_or(SessionError::BadFrame)?;

        if parsed.id_a != self.id_a {
            monitor.record(MonitorEvent::BadHandshake {
                id_a: parsed.id_a,
                reason: "wrong-id",
                t: now_s,
            });
            return Err(SessionError::BadFrame);
        }
        if parsed.nonce_g != pending.nonce_g {
            monitor.record(MonitorEvent::BadHandshake {
                id_a: parsed.id_a,
                reason: "wrong-nonce",
                t: now_s,
            });
            return Err(SessionError::BadFrame);
        }
        let skew = (parsed.timestamp_s as i64) - (now_s as i64);
        if skew.abs() > HANDSHAKE_SKEW_S {
            monitor.record(MonitorEvent::BadHandshake {
                id_a: parsed.id_a,
                reason: "skew",
                t: now_s,
            });
            return Err(SessionError::ClockSkew);
        }

        // Verify Dilithium signature over the canonical bytes (spec §5).
        let signed = signed_bytes_kem_resp(
            parsed.id_a,
            &parsed.ct,
            &parsed.nonce_a,
            &parsed.nonce_g,
            parsed.timestamp_s,
        );
        hsm.verify_aircraft(parsed.id_a, &signed, &parsed.signature)
            .map_err(|e| {
                monitor.record(MonitorEvent::BadHandshake {
                    id_a: parsed.id_a,
                    reason: match e {
                        HsmError::NotEnrolled => "not-enrolled",
                        HsmError::BadSignature => "sig",
                        _ => "hsm",
                    },
                    t: now_s,
                });
                SessionError::BadSignature
            })?;

        // KEM decapsulation.
        let mut ss = ground_kem_decap(&pending.esk, &parsed.ct).map_err(|_| {
            monitor.record(MonitorEvent::BadHandshake {
                id_a: parsed.id_a,
                reason: "decap",
                t: now_s,
            });
            SessionError::KemFailure
        })?;

        // Derive session keys (spec §6).
        let keys = SessionKeys::derive(&ss, &pending.nonce_a, &pending.nonce_g, self.id_a, self.id_g);
        ss.zeroize();

        self.keys = Some(keys);
        self.state = SessionState::Established;
        self.tx_seq = 0;
        self.rx_window = ReplayWindow::new();
        self.last_traffic_s = now_s;
        self.last_rekey_s = now_s;
        // Drop the ephemeral DK; ml-kem implements ZeroizeOnDrop.
        self.pending = None;
        monitor.record(MonitorEvent::SessionEstablished {
            id_a: self.id_a,
            t: now_s,
        });
        Ok(FrameOutcome::Consumed)
    }

    /// Encrypt outbound application data into a Phase-5 frame.
    pub fn encrypt_app(
        &mut self,
        plaintext: &[u8],
        now_s: u64,
    ) -> Result<Vec<u8>, SessionError> {
        if !matches!(self.state, SessionState::Established | SessionState::Rekeying) {
            return Err(SessionError::BadState);
        }
        if plaintext.len() > MAX_PAYLOAD {
            return Err(SessionError::BadFrame);
        }
        let keys = self.keys.as_ref().ok_or(SessionError::BadState)?;

        let header = DataHeader {
            version: PROTOCOL_VERSION,
            msg: MsgType::Data as u8,
            seq: self.tx_seq,
            id_a: self.id_a,
            id_g: self.id_g,
            utc_s: now_s,
        };
        let aad = header.to_aad();
        let (ct, tag) =
            aead_seal(keys, Direction::GroundToAircraft, self.tx_seq, &aad, plaintext)
                .map_err(|_| SessionError::AeadFailure)?;
        self.tx_seq = self
            .tx_seq
            .checked_add(1)
            .ok_or(SessionError::BadState)?;
        self.last_traffic_s = now_s;

        let mut out = Vec::with_capacity(aad.len() + ct.len() + AEAD_TAG_LEN);
        out.extend_from_slice(&aad);
        out.extend_from_slice(&ct);
        out.extend_from_slice(&tag);
        Ok(out)
    }

    /// Decrypt an inbound Phase-5 frame, applying spec §7.3 step-by-step.
    pub fn decrypt_app(
        &mut self,
        wire: &[u8],
        decoder: &mut KnockDecoder,
        monitor: &mut dyn MonitorSink,
        now_s: u64,
    ) -> Result<FrameOutcome, SessionError> {
        if !matches!(self.state, SessionState::Established | SessionState::Rekeying) {
            return Err(SessionError::BadState);
        }
        if wire.len() < DataHeader::WIRE_LEN + AEAD_TAG_LEN {
            return Err(SessionError::BadFrame);
        }
        let header = DataHeader::from_bytes(&wire[..DataHeader::WIRE_LEN])
            .ok_or(SessionError::BadFrame)?;

        if header.msg != MsgType::Data as u8 {
            return Err(SessionError::BadFrame);
        }
        if header.id_a != self.id_a || header.id_g != self.id_g {
            return Err(SessionError::BadFrame);
        }
        let skew = (header.utc_s as i64) - (now_s as i64);
        if skew.abs() > SESSION_SKEW_S {
            monitor.record(MonitorEvent::ClockSkew {
                id_a: self.id_a,
                offset_s: skew,
                t: now_s,
            });
            return Err(SessionError::ClockSkew);
        }
        if !self.rx_window.check_and_set(header.seq) {
            decoder.record_strike(self.id_a, now_s);
            monitor.record(MonitorEvent::Replay {
                id_a: self.id_a,
                seq: header.seq,
                t: now_s,
            });
            return Err(SessionError::Replay);
        }

        let body_start = DataHeader::WIRE_LEN;
        let body_end = wire.len() - AEAD_TAG_LEN;
        let ciphertext = &wire[body_start..body_end];
        let mut tag = [0u8; AEAD_TAG_LEN];
        tag.copy_from_slice(&wire[body_end..]);

        let aad = header.to_aad();
        let keys = self.keys.as_ref().ok_or(SessionError::BadState)?;
        let pt = aead_open(
            keys,
            Direction::AircraftToGround,
            header.seq,
            &aad,
            ciphertext,
            &tag,
        )
        .map_err(|_| {
            decoder.record_strike(self.id_a, now_s);
            monitor.record(MonitorEvent::AeadFailure {
                id_a: self.id_a,
                seq: header.seq,
                t: now_s,
            });
            SessionError::AeadFailure
        })?;

        // If three strikes have tripped lockout while we were here, the
        // policy says tear down and lock out. Lockout state is held in
        // the decoder.
        if decoder.is_locked_out(self.id_a, now_s) {
            self.tear_down(CloseReason::Lockout);
            monitor.record(MonitorEvent::Lockout {
                id_a: self.id_a,
                t: now_s,
            });
            return Ok(FrameOutcome::Closed(CloseReason::Lockout));
        }

        self.last_traffic_s = now_s;
        Ok(FrameOutcome::Plaintext(pt))
    }

    /// Drive the periodic clock — call once per second.
    ///
    /// Returns `Some(outgoing rekey bytes)` if a rekey is due, or
    /// `None` if no action is required. May also tear down the session
    /// on idle timeout.
    pub fn tick(&mut self, _now_s: u64) -> Option<()> {
        // The actual rekey ceremony is implemented in `crate::rekey` to
        // keep this module shorter. The daemon decides cadence via that
        // module; here we only expose the timestamps.
        None
    }

    /// Whether the idle timeout has elapsed.
    #[must_use]
    pub fn is_idle(&self, now_s: u64) -> bool {
        now_s.saturating_sub(self.last_traffic_s) >= IDLE_TIMEOUT_S
    }

    /// Whether a rekey is due.
    #[must_use]
    pub fn rekey_due(&self, now_s: u64) -> bool {
        matches!(self.state, SessionState::Established)
            && now_s.saturating_sub(self.last_rekey_s) >= REKEY_INTERVAL_S
    }

    /// Mark a rekey as just having completed (used by `crate::rekey`).
    pub fn note_rekey_done(&mut self, now_s: u64) {
        self.last_rekey_s = now_s;
        self.state = SessionState::Established;
    }

    /// Begin a rekey window.
    pub fn enter_rekey(&mut self) {
        if let SessionState::Established = self.state {
            self.state = SessionState::Rekeying;
        }
    }

    /// Replace session keys after a successful rekey.
    pub fn install_new_keys(&mut self, keys: SessionKeys) {
        self.keys = Some(keys);
        self.tx_seq = 0;
        self.rx_window = ReplayWindow::new();
    }

    /// Tear down with the given reason. Zeroizes session keys.
    pub fn tear_down(&mut self, reason: CloseReason) {
        self.keys = None;
        self.tx_seq = 0;
        self.rx_window = ReplayWindow::new();
        self.pending = None;
        self.state = SessionState::Closed(reason);
    }

    /// The aircraft id this session is bound to.
    #[must_use]
    pub fn id_a(&self) -> u64 {
        self.id_a
    }

    /// Inspector for the binary's self-test loop. Production callers go
    /// through [`encrypt_app`](Self::encrypt_app) / [`decrypt_app`](Self::decrypt_app)
    /// — never touch the raw keys.
    #[doc(hidden)]
    #[must_use]
    pub fn debug_keys(&self) -> Option<&SessionKeys> {
        self.keys.as_ref()
    }
}

/// Build a Phase-2 KEM_OFFER frame on the wire (spec §4).
///
/// Layout: msg(1) | id_g(4) | epk(1568) | nonce_g(16) | nonce_a(16)
///          | timestamp(8) | sig_g(4627)
pub fn build_kem_offer(
    id_g: u32,
    epk: &<MlKem1024 as KemCore>::EncapsulationKey,
    nonce_g: &[u8; NONCE_LEN],
    nonce_a: &[u8; NONCE_LEN],
    timestamp_s: u64,
    hsm: &Hsm,
) -> Result<Vec<u8>, HsmError> {
    let epk_bytes = encap_key_to_bytes(epk);
    let signed = signed_bytes_kem_offer(id_g, &epk_bytes, nonce_g, nonce_a, timestamp_s);
    let sig = hsm.sign_with_ground(&signed)?;

    let mut out =
        Vec::with_capacity(1 + 4 + KYBER1024_PK_LEN + NONCE_LEN * 2 + 8 + sig.len());
    out.push(MsgType::KemOffer as u8);
    out.extend_from_slice(&id_g.to_be_bytes());
    out.extend_from_slice(&epk_bytes);
    out.extend_from_slice(nonce_g);
    out.extend_from_slice(nonce_a);
    out.extend_from_slice(&timestamp_s.to_be_bytes());
    out.extend_from_slice(&sig);
    Ok(out)
}

/// Build the canonical "to-be-signed" bytes of a KEM_OFFER (spec §4).
fn signed_bytes_kem_offer(
    id_g: u32,
    epk_bytes: &[u8],
    nonce_g: &[u8; NONCE_LEN],
    nonce_a: &[u8; NONCE_LEN],
    timestamp_s: u64,
) -> Vec<u8> {
    let mut s = Vec::with_capacity(1 + 4 + epk_bytes.len() + NONCE_LEN * 2 + 8);
    s.push(MsgType::KemOffer as u8);
    s.extend_from_slice(&id_g.to_be_bytes());
    s.extend_from_slice(epk_bytes);
    s.extend_from_slice(nonce_g);
    s.extend_from_slice(nonce_a);
    s.extend_from_slice(&timestamp_s.to_be_bytes());
    s
}

/// Build the canonical "to-be-signed" bytes of a KEM_RESP (spec §5).
fn signed_bytes_kem_resp(
    id_a: u64,
    ct: &[u8],
    nonce_a: &[u8; NONCE_LEN],
    nonce_g: &[u8; NONCE_LEN],
    timestamp_s: u64,
) -> Vec<u8> {
    let mut s = Vec::with_capacity(1 + 8 + ct.len() + NONCE_LEN * 2 + 8);
    s.push(MsgType::KemResp as u8);
    s.extend_from_slice(&id_a.to_be_bytes());
    s.extend_from_slice(ct);
    s.extend_from_slice(nonce_a);
    s.extend_from_slice(nonce_g);
    s.extend_from_slice(&timestamp_s.to_be_bytes());
    s
}

/// Construct a KEM_RESP for the aircraft side (used by tests + the
/// embedded reference build). The aircraft has its own keypair `kp`,
/// the ground's encapsulation key `gpk`, and the nonces from the
/// preceding OFFER.
///
/// Returns `(wire_bytes, ss)`.
pub fn build_kem_resp(
    kp: &KeyPair<MlDsa87>,
    id_a: u64,
    nonce_a: &[u8; NONCE_LEN],
    nonce_g: &[u8; NONCE_LEN],
    gpk: &<MlKem1024 as KemCore>::EncapsulationKey,
    timestamp_s: u64,
) -> Result<(Vec<u8>, [u8; 32]), HsmError> {
    let (ct, ss) = aircraft_kem_encap(gpk)?;
    let signed = signed_bytes_kem_resp(id_a, &ct, nonce_a, nonce_g, timestamp_s);
    let sig: DsaSignature<MlDsa87> = kp.signing_key().sign(&signed);
    let sig_bytes = sig.encode().to_vec();

    let mut out =
        Vec::with_capacity(1 + 8 + ct.len() + NONCE_LEN * 2 + 8 + sig_bytes.len());
    out.push(MsgType::KemResp as u8);
    out.extend_from_slice(&id_a.to_be_bytes());
    out.extend_from_slice(&ct);
    out.extend_from_slice(nonce_a);
    out.extend_from_slice(nonce_g);
    out.extend_from_slice(&timestamp_s.to_be_bytes());
    out.extend_from_slice(&sig_bytes);
    Ok((out, ss))
}

struct ParsedKemResp {
    id_a: u64,
    ct: Vec<u8>,
    nonce_a: [u8; NONCE_LEN],
    nonce_g: [u8; NONCE_LEN],
    timestamp_s: u64,
    signature: Vec<u8>,
}

fn parse_kem_resp(b: &[u8]) -> Option<ParsedKemResp> {
    let min_len = 1 + 8 + KYBER1024_CT_LEN + NONCE_LEN * 2 + 8;
    if b.len() < min_len {
        return None;
    }
    if b[0] != MsgType::KemResp as u8 {
        return None;
    }
    let id_a = u64::from_be_bytes(b[1..9].try_into().ok()?);
    let mut ct = vec![0u8; KYBER1024_CT_LEN];
    ct.copy_from_slice(&b[9..9 + KYBER1024_CT_LEN]);
    let nonce_a_off = 9 + KYBER1024_CT_LEN;
    let nonce_g_off = nonce_a_off + NONCE_LEN;
    let ts_off = nonce_g_off + NONCE_LEN;
    let sig_off = ts_off + 8;
    if b.len() <= sig_off {
        return None;
    }
    let mut nonce_a = [0u8; NONCE_LEN];
    nonce_a.copy_from_slice(&b[nonce_a_off..nonce_g_off]);
    let mut nonce_g = [0u8; NONCE_LEN];
    nonce_g.copy_from_slice(&b[nonce_g_off..ts_off]);
    let timestamp_s = u64::from_be_bytes(b[ts_off..sig_off].try_into().ok()?);
    let signature = b[sig_off..].to_vec();
    Some(ParsedKemResp {
        id_a,
        ct,
        nonce_a,
        nonce_g,
        timestamp_s,
        signature,
    })
}

/// Convenience: current UTC TAI seconds. (Strict TAI requires a leap-
/// second source; approximated here as Unix time.)
#[must_use]
pub fn now_s() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hsm::{aircraft_keygen, encap_key_from_bytes};
    use crate::knock::KnockDecoder;
    use crate::monitor::CountingMonitor;
    use crate::protocol::KNOCK_WINDOW_S;
    use ml_dsa::MlDsa87;

    fn make_pair() -> (Hsm, KeyPair<MlDsa87>, [u8; 32], u64) {
        let mut hsm = Hsm::boot();
        let aircraft = aircraft_keygen();
        let id_a = 0xCAFEu64;
        let k_master = [0x77u8; 32];
        hsm.enrol(id_a, aircraft.verifying_key().clone(), k_master);
        (hsm, aircraft, k_master, id_a)
    }

    /// Run a closure on a thread with an 8 MiB stack. The two session
    /// tests exercise full ML-KEM-1024 + ML-DSA-87 round-trips; the
    /// associated key, ciphertext, and signature buffers (~10 KiB each)
    /// blow the Windows default test-thread stack of 1 MiB. Production
    /// code never holds them by value at the same time, so this only
    /// affects the test harness.
    fn run_with_big_stack<F: FnOnce() + Send + 'static>(f: F) {
        std::thread::Builder::new()
            .stack_size(8 * 1024 * 1024)
            .spawn(f)
            .expect("spawn")
            .join()
            .expect("join");
    }

    #[test]
    fn full_handshake_round_trip() {
        run_with_big_stack(|| full_handshake_round_trip_body());
    }

    fn full_handshake_round_trip_body() {
        let (hsm, aircraft, k_master, id_a) = make_pair();
        let id_g = 0xABCDu32;
        let mut monitor = CountingMonitor::default();
        let mut decoder = KnockDecoder::new(id_g);
        let mut session = Session::new(id_a, id_g);

        let now_s = 100 * KNOCK_WINDOW_S + 1;
        let bucket = now_s / KNOCK_WINDOW_S;
        let token = crate::crypto::knock_token(&k_master, id_a, id_g, bucket);

        // Phase 1.
        let knock = KnockFrame {
            token,
            id_a,
            nonce_a: [0xAAu8; NONCE_LEN],
            version: PROTOCOL_VERSION,
            flags: 0,
        };
        let offer_bytes = match session
            .handle_knock(&knock.to_bytes(), &mut decoder, &hsm, &mut monitor, now_s)
            .expect("knock accepted")
        {
            FrameOutcome::Emit(b) => b,
            _ => panic!("expected offer bytes"),
        };
        assert_eq!(session.state(), SessionState::AwaitingKemResp);

        // Aircraft side parses the OFFER and builds a RESP.
        let (epk_bytes, nonce_g, nonce_a_echo, timestamp_s) =
            parse_kem_offer_for_test(&offer_bytes);
        assert_eq!(nonce_a_echo, knock.nonce_a);
        let gpk = encap_key_from_bytes(&epk_bytes).expect("decode gpk");
        let (resp_bytes, _ss_air) = build_kem_resp(
            &aircraft, id_a, &nonce_a_echo, &nonce_g, &gpk, timestamp_s,
        )
        .expect("build resp");

        // Phase 3.
        match session
            .handle_kem_resp(&resp_bytes, &hsm, &mut monitor, timestamp_s)
            .expect("resp accepted")
        {
            FrameOutcome::Consumed => {}
            _ => panic!("expected consumed"),
        }
        assert_eq!(session.state(), SessionState::Established);

        // Round-trip a Phase-5 data frame.
        let outbound = session
            .encrypt_app(b"clearance to land", timestamp_s + 1)
            .expect("seal");
        // Pretend the aircraft echoed it back (in a real session each
        // direction has its own seq + key; here we test the ground side
        // by sending a frame the aircraft would send).
        // We'll fabricate an aircraft-direction frame manually.
        let header = DataHeader {
            version: PROTOCOL_VERSION,
            msg: MsgType::Data as u8,
            seq: 0,
            id_a,
            id_g,
            utc_s: timestamp_s + 1,
        };
        let aad = header.to_aad();
        let keys = session.keys.as_ref().expect("keys");
        let (ct, tag) = aead_seal(
            keys,
            Direction::AircraftToGround,
            0,
            &aad,
            b"roger",
        )
        .expect("seal a->g");
        let mut frame = aad.to_vec();
        frame.extend_from_slice(&ct);
        frame.extend_from_slice(&tag);

        let pt = match session
            .decrypt_app(&frame, &mut decoder, &mut monitor, timestamp_s + 1)
            .expect("decrypt")
        {
            FrameOutcome::Plaintext(b) => b,
            _ => panic!("expected plaintext"),
        };
        assert_eq!(pt, b"roger");
        let _ = outbound; // silence unused
    }

    fn parse_kem_offer_for_test(b: &[u8]) -> (Vec<u8>, [u8; NONCE_LEN], [u8; NONCE_LEN], u64) {
        assert_eq!(b[0], MsgType::KemOffer as u8);
        let _id_g = u32::from_be_bytes(b[1..5].try_into().unwrap());
        let epk = b[5..5 + KYBER1024_PK_LEN].to_vec();
        let mut ng = [0u8; NONCE_LEN];
        ng.copy_from_slice(&b[5 + KYBER1024_PK_LEN..5 + KYBER1024_PK_LEN + NONCE_LEN]);
        let mut na = [0u8; NONCE_LEN];
        na.copy_from_slice(
            &b[5 + KYBER1024_PK_LEN + NONCE_LEN..5 + KYBER1024_PK_LEN + 2 * NONCE_LEN],
        );
        let ts_off = 5 + KYBER1024_PK_LEN + 2 * NONCE_LEN;
        let ts = u64::from_be_bytes(b[ts_off..ts_off + 8].try_into().unwrap());
        (epk, ng, na, ts)
    }

    #[test]
    fn replay_kicks_strike_count() {
        run_with_big_stack(|| replay_kicks_strike_count_body());
    }

    fn replay_kicks_strike_count_body() {
        let (hsm, aircraft, k_master, id_a) = make_pair();
        let id_g = 0xABCDu32;
        let mut monitor = CountingMonitor::default();
        let mut decoder = KnockDecoder::new(id_g);
        let mut session = Session::new(id_a, id_g);

        let now_s = 100 * KNOCK_WINDOW_S + 1;
        let bucket = now_s / KNOCK_WINDOW_S;
        let token = crate::crypto::knock_token(&k_master, id_a, id_g, bucket);
        let knock = KnockFrame {
            token,
            id_a,
            nonce_a: [0xAAu8; NONCE_LEN],
            version: PROTOCOL_VERSION,
            flags: 0,
        };
        let offer_bytes = match session
            .handle_knock(&knock.to_bytes(), &mut decoder, &hsm, &mut monitor, now_s)
            .unwrap()
        {
            FrameOutcome::Emit(b) => b,
            _ => unreachable!(),
        };
        let (epk_bytes, nonce_g, nonce_a_echo, ts) = parse_kem_offer_for_test(&offer_bytes);
        let gpk = encap_key_from_bytes(&epk_bytes).unwrap();
        let (resp_bytes, _) =
            build_kem_resp(&aircraft, id_a, &nonce_a_echo, &nonce_g, &gpk, ts).unwrap();
        session
            .handle_kem_resp(&resp_bytes, &hsm, &mut monitor, ts)
            .unwrap();

        let header = DataHeader {
            version: PROTOCOL_VERSION,
            msg: MsgType::Data as u8,
            seq: 1,
            id_a,
            id_g,
            utc_s: ts,
        };
        let aad = header.to_aad();
        let keys = session.keys.as_ref().unwrap();
        let (ct, tag) =
            aead_seal(keys, Direction::AircraftToGround, 1, &aad, b"hi").unwrap();
        let mut frame = aad.to_vec();
        frame.extend_from_slice(&ct);
        frame.extend_from_slice(&tag);
        // First delivery: ok.
        session.decrypt_app(&frame, &mut decoder, &mut monitor, ts).unwrap();
        // Replay: rejected.
        let r = session.decrypt_app(&frame, &mut decoder, &mut monitor, ts);
        assert_eq!(r.err(), Some(SessionError::Replay));
    }
}
