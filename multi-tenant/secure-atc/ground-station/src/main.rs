//! SHADOW-ATC ground-station daemon.
//!
//! Boots the HSM, enrols a demo aircraft, and runs a self-test
//! handshake end-to-end on `localhost`-equivalent in-memory channels.
//! In production the radio + dark-fibre interfaces replace these.
//!
//! The binary is a developer harness — it proves the protocol logic
//! works without requiring physical hardware. The library in
//! [`shadow_atc_ground`] is what an operational deployment would link.

#![forbid(unsafe_code)]

use shadow_atc_ground::{
    crypto::{aead_seal, knock_token, Direction},
    hsm::{aircraft_keygen, boot_measurement, encap_key_from_bytes, Hsm},
    knock::KnockDecoder,
    monitor::{MonitorEvent, MonitorSink, StderrMonitor},
    protocol::{
        DataHeader, KnockFrame, MsgType, KNOCK_WINDOW_S, KYBER1024_PK_LEN, NONCE_LEN,
        PROTOCOL_VERSION,
    },
    session::{build_kem_resp, now_s, FrameOutcome, Session, SessionState},
};

fn main() {
    let mut monitor = StderrMonitor;

    // ── Boot sequence (HSM doc §5) ───────────────────────────────────
    let mut hsm = Hsm::boot();
    let measurement = boot_measurement(&hsm);
    monitor.record(MonitorEvent::BootAttestation {
        measurement,
        t: now_s(),
    });

    // ── Demo aircraft enrolment ──────────────────────────────────────
    let aircraft = aircraft_keygen();
    let id_a = 0xCAFE_BABEu64;
    let id_g = 0xDEAD_BEEFu32;
    let k_master = [0x77u8; 32];
    hsm.enrol(id_a, aircraft.verifying_key().clone(), k_master);
    eprintln!(
        "enrolled aircraft id_a={id_a:#018x} ground id_g={id_g:#010x}"
    );

    // ── Self-test handshake ──────────────────────────────────────────
    let mut decoder = KnockDecoder::new(id_g);
    let mut session = Session::new(id_a, id_g);

    let t = now_s();
    let bucket = t / KNOCK_WINDOW_S;
    let token = knock_token(&k_master, id_a, id_g, bucket);

    let knock = KnockFrame {
        token,
        id_a,
        nonce_a: [0xAAu8; NONCE_LEN],
        version: PROTOCOL_VERSION,
        flags: 0,
    };

    eprintln!("--> Phase 1: KNOCK");
    let offer_bytes = match session
        .handle_knock(&knock.to_bytes(), &mut decoder, &hsm, &mut monitor, t)
        .expect("knock accepted")
    {
        FrameOutcome::Emit(b) => b,
        _ => panic!("expected KEM_OFFER bytes"),
    };
    eprintln!("<-- Phase 2: KEM_OFFER ({} bytes)", offer_bytes.len());
    assert_eq!(session.state(), SessionState::AwaitingKemResp);

    // Aircraft side parses the offer and builds RESP.
    let (epk_bytes, nonce_g, nonce_a_echo, ts) = parse_kem_offer(&offer_bytes);
    let gpk = encap_key_from_bytes(&epk_bytes).expect("decode gpk");
    let (resp_bytes, _ss_air) =
        build_kem_resp(&aircraft, id_a, &nonce_a_echo, &nonce_g, &gpk, ts)
            .expect("build resp");
    eprintln!("--> Phase 3: KEM_RESP ({} bytes)", resp_bytes.len());

    match session
        .handle_kem_resp(&resp_bytes, &hsm, &mut monitor, ts)
        .expect("resp accepted")
    {
        FrameOutcome::Consumed => {}
        _ => panic!("expected consumed"),
    }
    assert_eq!(session.state(), SessionState::Established);
    eprintln!("    Phase 4: keys derived; session established");

    // Phase 5 round-trip.
    let app = b"CLEARED TO LAND RWY 13L QNH 30.05";
    let outbound = session.encrypt_app(app, ts + 1).expect("seal");
    eprintln!("<-- Phase 5: data ({} bytes ciphertext+tag)", outbound.len());

    // Aircraft replies (we synthesize the inverse direction here).
    let header = DataHeader {
        version: PROTOCOL_VERSION,
        msg: MsgType::Data as u8,
        seq: 0,
        id_a,
        id_g,
        utc_s: ts + 1,
    };
    let aad = header.to_aad();
    let keys = session.debug_keys().expect("established");
    let (ct, tag) =
        aead_seal(keys, Direction::AircraftToGround, 0, &aad, b"ROGER 13L 30.05")
            .expect("seal a->g");
    let mut frame = aad.to_vec();
    frame.extend_from_slice(&ct);
    frame.extend_from_slice(&tag);
    let pt = match session
        .decrypt_app(&frame, &mut decoder, &mut monitor, ts + 1)
        .expect("open")
    {
        FrameOutcome::Plaintext(b) => b,
        _ => panic!("expected plaintext"),
    };
    eprintln!(
        "    Phase 5 reverse: \"{}\"",
        String::from_utf8_lossy(&pt)
    );

    eprintln!("self-test OK");
}

fn parse_kem_offer(b: &[u8]) -> (Vec<u8>, [u8; NONCE_LEN], [u8; NONCE_LEN], u64) {
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

