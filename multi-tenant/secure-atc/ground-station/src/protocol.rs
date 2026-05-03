//! Wire-format constants for SHADOW-COMM v1.
//!
//! See `../docs/01-crypto-protocol.md` Appendix A. The values here are the
//! single source of truth for the daemon; OTP fuse readback at boot must
//! match these or the daemon refuses to start.

/// Protocol version. Burned into the OTP fuse bank; mismatched versions
/// are dropped pre-handshake.
pub const PROTOCOL_VERSION: u8 = 0x01;

/// Reserved zero in the lower bits of the version byte.
pub const RESERVED_ZERO: u8 = 0x00;

/// Knock token window length. Both `B` and `B-1` are accepted.
pub const KNOCK_WINDOW_S: u64 = 30;

/// Time-skew tolerance during the handshake (Phases 2 and 3).
pub const HANDSHAKE_SKEW_S: i64 = 5;

/// Time-skew tolerance once the session is established. Tighter than
/// the handshake window because clock skew has been measured.
pub const SESSION_SKEW_S: i64 = 3;

/// Forward-secret rekey period.
pub const REKEY_INTERVAL_S: u64 = 30;

/// A session that goes idle this long is closed with reason 0x03.
pub const IDLE_TIMEOUT_S: u64 = 90;

/// Strike count that triggers a per-aircraft lockout.
pub const LOCKOUT_AFTER_STRIKES: u32 = 3;

/// Sliding-window size for strike accumulation.
pub const LOCKOUT_WINDOW_S: u64 = 60;

/// How long an aircraft is locked out after tripping the strike count.
pub const LOCKOUT_HOLD_S: u64 = 600;

/// Replay-protection window in frames per direction.
pub const REPLAY_WINDOW: u64 = 256;

/// Max plaintext per data frame (keeps frame ≤ aviation MTU).
pub const MAX_PAYLOAD: usize = 1200;

/// Length of the truncated knock token on the wire.
pub const KNOCK_TOKEN_LEN: usize = 8;

/// Length of the per-direction nonces exchanged during handshake.
pub const NONCE_LEN: usize = 16;

/// Length of an AES-GCM auth tag.
pub const AEAD_TAG_LEN: usize = 16;

/// Length of an AES-GCM IV (NIST 96-bit recommendation).
pub const AEAD_IV_LEN: usize = 12;

/// AES-256 key length.
pub const AEAD_KEY_LEN: usize = 32;

/// Dilithium-5 signature length (FIPS 204 / ML-DSA-87).
pub const DILITHIUM5_SIG_LEN: usize = 4627;

/// Dilithium-5 public-key length (FIPS 204 / ML-DSA-87).
pub const DILITHIUM5_PK_LEN: usize = 2592;

/// Kyber-1024 ciphertext length (FIPS 203 / ML-KEM-1024).
pub const KYBER1024_CT_LEN: usize = 1568;

/// Kyber-1024 public-key length (FIPS 203 / ML-KEM-1024).
pub const KYBER1024_PK_LEN: usize = 1568;

/// Kyber-1024 / ML-KEM shared-secret length.
pub const KEM_SHARED_LEN: usize = 32;

/// Wire message types (spec §A).
#[repr(u8)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum MsgType {
    /// Phase 1 knock — implicit; the type byte is the version (0x01) and
    /// the frame layout is specialized per spec §3.2.
    Knock = 0x01,
    /// Phase 2 KEM_OFFER (ground → aircraft).
    KemOffer = 0x10,
    /// Phase 3 KEM_RESP (aircraft → ground).
    KemResp = 0x11,
    /// Phase 5 authenticated data.
    Data = 0x20,
    /// Phase 5b rekey offer (ground → aircraft, AEAD-protected).
    RekeyOffer = 0x30,
    /// Phase 5b rekey response (aircraft → ground, AEAD-protected).
    RekeyResp = 0x31,
    /// Phase 6 close (signed inside an AEAD frame).
    Close = 0x40,
}

impl MsgType {
    /// Parse a wire-byte into a `MsgType`.
    #[must_use]
    pub fn from_u8(b: u8) -> Option<Self> {
        Some(match b {
            0x01 => Self::Knock,
            0x10 => Self::KemOffer,
            0x11 => Self::KemResp,
            0x20 => Self::Data,
            0x30 => Self::RekeyOffer,
            0x31 => Self::RekeyResp,
            0x40 => Self::Close,
            _ => return None,
        })
    }
}

/// Reason byte in a Phase-6 CLOSE.
#[repr(u8)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum CloseReason {
    /// Normal termination, end of flight or maintenance handoff.
    Normal = 0x00,
    /// Strike count reached lockout threshold.
    Lockout = 0x01,
    /// HSM tamper switch fired or attestation failed.
    HardwareTamper = 0x02,
    /// 90-second idle timeout elapsed.
    LinkTimeout = 0x03,
    /// RF blackout retained too long; session torn down.
    RfBlackout = 0x04,
}

/// A Phase-1 KNOCK frame as seen on the wire.
///
/// 36 bytes total. Layout matches spec §3.2.
#[derive(Copy, Clone, Debug)]
pub struct KnockFrame {
    /// HMAC-SHA3-256 truncated to 8 bytes (spec §3.1).
    pub token: [u8; KNOCK_TOKEN_LEN],
    /// Aircraft identifier (transponder serial).
    pub id_a: u64,
    /// Random per-session nonce.
    pub nonce_a: [u8; NONCE_LEN],
    /// Protocol version byte.
    pub version: u8,
    /// Bit 0: rejoining after RF blackout. Other bits reserved.
    pub flags: u8,
}

impl KnockFrame {
    /// Wire size in bytes.
    pub const WIRE_LEN: usize = KNOCK_TOKEN_LEN + 8 + NONCE_LEN + 2 + 2;

    /// Serialize to wire bytes. Big-endian throughout.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; Self::WIRE_LEN] {
        let mut out = [0u8; Self::WIRE_LEN];
        out[0..8].copy_from_slice(&self.token);
        out[8..16].copy_from_slice(&self.id_a.to_be_bytes());
        out[16..32].copy_from_slice(&self.nonce_a);
        out[32] = self.version;
        out[33] = self.flags;
        // bytes 34..36 reserved zero
        out
    }

    /// Parse from wire bytes. Returns `None` on length, version, or
    /// reserved-bit violations.
    #[must_use]
    pub fn from_bytes(b: &[u8]) -> Option<Self> {
        if b.len() != Self::WIRE_LEN {
            return None;
        }
        if b[32] != PROTOCOL_VERSION {
            return None;
        }
        if b[34] != 0 || b[35] != 0 {
            return None;
        }
        let mut token = [0u8; KNOCK_TOKEN_LEN];
        token.copy_from_slice(&b[0..8]);
        let id_a = u64::from_be_bytes(b[8..16].try_into().ok()?);
        let mut nonce_a = [0u8; NONCE_LEN];
        nonce_a.copy_from_slice(&b[16..32]);
        Some(Self {
            token,
            id_a,
            nonce_a,
            version: b[32],
            flags: b[33],
        })
    }
}

/// Generic header for Phase-5 data frames.
///
/// Matches spec §7.1. The header *is* the AAD for the AEAD step.
#[derive(Copy, Clone, Debug)]
pub struct DataHeader {
    /// Protocol version.
    pub version: u8,
    /// `MsgType` byte.
    pub msg: u8,
    /// Monotonic frame counter, per session per direction.
    pub seq: u64,
    /// Aircraft id.
    pub id_a: u64,
    /// Ground-station id.
    pub id_g: u32,
    /// UTC TAI second.
    pub utc_s: u64,
}

impl DataHeader {
    /// Wire size of the header in bytes.
    pub const WIRE_LEN: usize = 1 + 1 + 2 + 8 + 8 + 4 + 8;

    /// Serialize header to its wire bytes — used as AAD.
    #[must_use]
    pub fn to_aad(&self) -> [u8; Self::WIRE_LEN] {
        let mut out = [0u8; Self::WIRE_LEN];
        out[0] = self.version;
        out[1] = self.msg;
        // bytes 2..4 reserved zero
        out[4..12].copy_from_slice(&self.seq.to_be_bytes());
        out[12..20].copy_from_slice(&self.id_a.to_be_bytes());
        out[20..24].copy_from_slice(&self.id_g.to_be_bytes());
        out[24..32].copy_from_slice(&self.utc_s.to_be_bytes());
        out
    }

    /// Parse a header off a wire frame. Checks version + reserved bits.
    #[must_use]
    pub fn from_bytes(b: &[u8]) -> Option<Self> {
        if b.len() < Self::WIRE_LEN {
            return None;
        }
        if b[0] != PROTOCOL_VERSION || b[2] != 0 || b[3] != 0 {
            return None;
        }
        Some(Self {
            version: b[0],
            msg: b[1],
            seq: u64::from_be_bytes(b[4..12].try_into().ok()?),
            id_a: u64::from_be_bytes(b[12..20].try_into().ok()?),
            id_g: u32::from_be_bytes(b[20..24].try_into().ok()?),
            utc_s: u64::from_be_bytes(b[24..32].try_into().ok()?),
        })
    }
}

/// A complete frame that has been authenticated (header + ciphertext + tag).
#[derive(Clone, Debug)]
pub struct Frame {
    /// Authenticated header (used as AAD).
    pub header: DataHeader,
    /// Ciphertext bytes (no tag).
    pub ciphertext: Vec<u8>,
    /// 16-byte AEAD tag.
    pub tag: [u8; AEAD_TAG_LEN],
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn knock_round_trip() {
        let f = KnockFrame {
            token: [1, 2, 3, 4, 5, 6, 7, 8],
            id_a: 0xCAFE_BABE_DEAD_BEEF,
            nonce_a: [0xAA; NONCE_LEN],
            version: PROTOCOL_VERSION,
            flags: 0,
        };
        let bytes = f.to_bytes();
        let parsed = KnockFrame::from_bytes(&bytes).expect("parse");
        assert_eq!(parsed.token, f.token);
        assert_eq!(parsed.id_a, f.id_a);
        assert_eq!(parsed.nonce_a, f.nonce_a);
    }

    #[test]
    fn knock_rejects_bad_version() {
        let mut bytes = KnockFrame {
            token: [0; 8],
            id_a: 1,
            nonce_a: [0; NONCE_LEN],
            version: PROTOCOL_VERSION,
            flags: 0,
        }
        .to_bytes();
        bytes[32] = 0x99;
        assert!(KnockFrame::from_bytes(&bytes).is_none());
    }

    #[test]
    fn knock_rejects_nonzero_reserved() {
        let mut bytes = KnockFrame {
            token: [0; 8],
            id_a: 1,
            nonce_a: [0; NONCE_LEN],
            version: PROTOCOL_VERSION,
            flags: 0,
        }
        .to_bytes();
        bytes[35] = 0x01;
        assert!(KnockFrame::from_bytes(&bytes).is_none());
    }

    #[test]
    fn data_header_aad_is_stable() {
        let h = DataHeader {
            version: PROTOCOL_VERSION,
            msg: MsgType::Data as u8,
            seq: 42,
            id_a: 0x1122_3344_5566_7788,
            id_g: 0xDEAD_BEEF,
            utc_s: 1_700_000_000,
        };
        let aad = h.to_aad();
        let parsed = DataHeader::from_bytes(&aad).expect("parse");
        assert_eq!(parsed.seq, h.seq);
        assert_eq!(parsed.id_a, h.id_a);
        assert_eq!(parsed.id_g, h.id_g);
        assert_eq!(parsed.utc_s, h.utc_s);
    }
}
