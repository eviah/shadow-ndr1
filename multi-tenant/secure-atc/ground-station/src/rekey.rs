//! 30-second forward-secret rekey loop (spec §5b).
//!
//! The rekey ceremony is structurally a Phase-2/Phase-3 mini-handshake
//! wrapped inside the existing AEAD session. A failure on either side
//! tears the session down — there is no fall-back to old keys.

use ml_kem::{KemCore, MlKem1024};
use rand::RngCore;
use rand::rngs::OsRng;
use zeroize::Zeroize;

use crate::crypto::{aead_open, aead_seal, Direction, SessionKeys};
use crate::hsm::{
    aircraft_kem_encap, encap_key_from_bytes, encap_key_to_bytes, ground_kem_decap,
    ground_kem_keygen, HsmError,
};
use crate::monitor::{MonitorEvent, MonitorSink};
use crate::protocol::{
    AEAD_TAG_LEN, KEM_SHARED_LEN, KYBER1024_CT_LEN, KYBER1024_PK_LEN, MsgType,
    NONCE_LEN, PROTOCOL_VERSION,
};
use crate::protocol::{CloseReason, DataHeader};
use crate::session::{FrameOutcome, Session, SessionError, SessionState};

/// Pending rekey state on the ground side. Held only between the
/// REKEY_OFFER and the REKEY_RESP.
pub struct PendingRekey {
    nonce_g: [u8; NONCE_LEN],
    esk: <MlKem1024 as KemCore>::DecapsulationKey,
}

/// Build a Phase-5b REKEY_OFFER and emit it as an AEAD-protected frame
/// using the *current* session key. After the new keys are installed,
/// the old `K_s` is zeroized (spec §5b step 3).
pub fn build_rekey_offer(
    session: &mut Session,
    now_s: u64,
) -> Result<(Vec<u8>, PendingRekey), SessionError> {
    if session.state() != SessionState::Established {
        return Err(SessionError::BadState);
    }
    let (esk, epk) = ground_kem_keygen();
    let mut nonce_g = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce_g);

    let epk_bytes = encap_key_to_bytes(&epk);
    let mut payload = Vec::with_capacity(KYBER1024_PK_LEN + NONCE_LEN);
    payload.extend_from_slice(&epk_bytes);
    payload.extend_from_slice(&nonce_g);

    // AEAD-wrap with the current key (G->A), under a Data-shaped header
    // tagged as REKEY_OFFER (msg = 0x30).
    let header = DataHeader {
        version: PROTOCOL_VERSION,
        msg: MsgType::RekeyOffer as u8,
        seq: session.tx_seq,
        id_a: session.id_a,
        id_g: session.id_g,
        utc_s: now_s,
    };
    let aad = header.to_aad();
    let keys = session
        .keys
        .as_ref()
        .ok_or(SessionError::BadState)?;
    let (ct, tag) = aead_seal(
        keys,
        Direction::GroundToAircraft,
        session.tx_seq,
        &aad,
        &payload,
    )
    .map_err(|_| SessionError::AeadFailure)?;
    session.tx_seq = session.tx_seq.checked_add(1).ok_or(SessionError::BadState)?;
    session.enter_rekey();

    let mut wire = aad.to_vec();
    wire.extend_from_slice(&ct);
    wire.extend_from_slice(&tag);

    Ok((wire, PendingRekey { nonce_g, esk }))
}

/// Process an inbound REKEY_RESP. On success, derive new keys and
/// install them; the old keys' `Zeroizing` wrappers wipe themselves
/// on drop.
pub fn handle_rekey_resp(
    session: &mut Session,
    pending: PendingRekey,
    wire: &[u8],
    monitor: &mut dyn MonitorSink,
    now_s: u64,
) -> Result<FrameOutcome, SessionError> {
    if session.state() != SessionState::Rekeying {
        return Err(SessionError::BadState);
    }
    if wire.len() < DataHeader::WIRE_LEN + AEAD_TAG_LEN {
        return Err(SessionError::BadFrame);
    }
    let header = DataHeader::from_bytes(&wire[..DataHeader::WIRE_LEN])
        .ok_or(SessionError::BadFrame)?;
    if header.msg != MsgType::RekeyResp as u8 || header.id_a != session.id_a {
        return Err(SessionError::BadFrame);
    }

    let body_start = DataHeader::WIRE_LEN;
    let body_end = wire.len() - AEAD_TAG_LEN;
    let ciphertext = &wire[body_start..body_end];
    let mut tag = [0u8; AEAD_TAG_LEN];
    tag.copy_from_slice(&wire[body_end..]);
    let aad = header.to_aad();
    let keys = session.keys.as_ref().ok_or(SessionError::BadState)?;

    let pt = aead_open(
        keys,
        Direction::AircraftToGround,
        header.seq,
        &aad,
        ciphertext,
        &tag,
    )
    .map_err(|_| {
        monitor.record(MonitorEvent::AeadFailure {
            id_a: session.id_a,
            seq: header.seq,
            t: now_s,
        });
        // Spec §5b: rekey failure tears the session down.
        session.tear_down(CloseReason::Lockout);
        SessionError::AeadFailure
    })?;

    if pt.len() != KYBER1024_CT_LEN + NONCE_LEN {
        session.tear_down(CloseReason::Lockout);
        return Err(SessionError::BadFrame);
    }
    let (ct, nonce_a) = pt.split_at(KYBER1024_CT_LEN);
    let mut nonce_a_arr = [0u8; NONCE_LEN];
    nonce_a_arr.copy_from_slice(nonce_a);

    let mut ss = ground_kem_decap(&pending.esk, ct).map_err(|_| {
        session.tear_down(CloseReason::Lockout);
        SessionError::KemFailure
    })?;
    let new_keys = SessionKeys::derive(
        &ss,
        &nonce_a_arr,
        &pending.nonce_g,
        session.id_a,
        session.id_g,
    );
    ss.zeroize();

    session.install_new_keys(new_keys);
    session.note_rekey_done(now_s);
    monitor.record(MonitorEvent::RekeyComplete {
        id_a: session.id_a,
        t: now_s,
    });
    Ok(FrameOutcome::Consumed)
}

/// Aircraft-side construction of REKEY_RESP for tests + the embedded
/// reference. Returns the AEAD-wrapped wire frame and the freshly
/// derived session keys (which the aircraft installs immediately upon
/// emission).
pub fn build_rekey_resp_for_aircraft(
    current: &SessionKeys,
    id_a: u64,
    id_g: u32,
    seq: u64,
    now_s: u64,
    gpk_bytes: &[u8],
    nonce_g: &[u8; NONCE_LEN],
) -> Result<(Vec<u8>, [u8; KEM_SHARED_LEN], [u8; NONCE_LEN]), HsmError> {
    let gpk = encap_key_from_bytes(gpk_bytes)?;
    let (ct, ss) = aircraft_kem_encap(&gpk)?;
    let mut nonce_a = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce_a);

    let mut payload = Vec::with_capacity(KYBER1024_CT_LEN + NONCE_LEN);
    payload.extend_from_slice(&ct);
    payload.extend_from_slice(&nonce_a);

    let header = DataHeader {
        version: PROTOCOL_VERSION,
        msg: MsgType::RekeyResp as u8,
        seq,
        id_a,
        id_g,
        utc_s: now_s,
    };
    let aad = header.to_aad();
    let (ct_wire, tag) =
        aead_seal(current, Direction::AircraftToGround, seq, &aad, &payload)
            .map_err(|_| HsmError::KemFailure)?;
    let mut wire = aad.to_vec();
    wire.extend_from_slice(&ct_wire);
    wire.extend_from_slice(&tag);
    let _ = nonce_g;
    Ok((wire, ss, nonce_a))
}
