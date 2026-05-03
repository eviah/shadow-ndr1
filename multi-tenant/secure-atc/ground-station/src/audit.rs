//! End-to-end Merkle audit trail (frontier upgrade #22).
//!
//! Every operationally significant event — session establishment, rekey
//! completion, lockout, CLOSE, monitor incident — is appended to a
//! SHA3-256 hashchain. Each entry binds to its predecessor, so any
//! tampering with the middle of the log invalidates every entry after
//! the tampered one. The chain head is replicated to peer ground sites
//! and notarized by RFC-3161 timestamp authorities at hour boundaries.

use sha3::{Digest, Sha3_256};

/// Event categories the audit log accepts.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum AuditKind {
    SessionEstablished = 0x01,
    RekeyComplete = 0x02,
    Lockout = 0x03,
    Close = 0x04,
    BadKnock = 0x05,
    Replay = 0x06,
    AeadFailure = 0x07,
    ClockSkew = 0x08,
    HsmTamper = 0x09,
}

impl AuditKind {
    pub fn as_u8(self) -> u8 {
        self as u8
    }
}

/// One entry in the chain. `prev` is `[0u8; 32]` for the genesis entry.
#[derive(Clone, Debug)]
pub struct AuditEntry {
    pub prev: [u8; 32],
    pub kind: AuditKind,
    pub t_utc_s: u64,
    pub id_a: u64,
    pub id_g: u32,
    pub seq: u64,
    pub payload: Vec<u8>,
}

impl AuditEntry {
    /// Compute the chain hash that this entry's *successor* will use as
    /// its `prev` field.
    pub fn entry_hash(&self) -> [u8; 32] {
        let mut h = Sha3_256::new();
        h.update(b"shadow-comm/v1/audit");
        h.update(self.prev);
        h.update([self.kind.as_u8()]);
        h.update(self.t_utc_s.to_be_bytes());
        h.update(self.id_a.to_be_bytes());
        h.update(self.id_g.to_be_bytes());
        h.update(self.seq.to_be_bytes());
        h.update((self.payload.len() as u32).to_be_bytes());
        h.update(&self.payload);
        let out = h.finalize();
        let mut a = [0u8; 32];
        a.copy_from_slice(&out);
        a
    }
}

/// Append-only audit log.
pub struct AuditLog {
    pub head: [u8; 32],
    pub entries: Vec<AuditEntry>,
}

impl Default for AuditLog {
    fn default() -> Self {
        Self::new()
    }
}

impl AuditLog {
    pub fn new() -> Self {
        Self {
            head: [0u8; 32],
            entries: Vec::new(),
        }
    }

    /// Append an event. The entry's `prev` is set to the current head;
    /// the head advances to the new entry's hash.
    pub fn append(
        &mut self,
        kind: AuditKind,
        t_utc_s: u64,
        id_a: u64,
        id_g: u32,
        seq: u64,
        payload: Vec<u8>,
    ) -> [u8; 32] {
        let entry = AuditEntry {
            prev: self.head,
            kind,
            t_utc_s,
            id_a,
            id_g,
            seq,
            payload,
        };
        let h = entry.entry_hash();
        self.entries.push(entry);
        self.head = h;
        h
    }

    /// Replay every entry from index 0, returning the index of the
    /// first entry whose `prev` does not match the running hash, or
    /// `Ok(())` if the chain is intact.
    pub fn verify(&self) -> Result<(), usize> {
        let mut running = [0u8; 32];
        for (i, e) in self.entries.iter().enumerate() {
            if e.prev != running {
                return Err(i);
            }
            running = e.entry_hash();
        }
        if running != self.head {
            return Err(self.entries.len());
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn populate(log: &mut AuditLog) {
        log.append(AuditKind::SessionEstablished, 100, 0xCAFE, 0xABCD, 0, vec![]);
        log.append(AuditKind::RekeyComplete, 130, 0xCAFE, 0xABCD, 0, vec![]);
        log.append(
            AuditKind::BadKnock,
            150,
            0xDEAD,
            0xABCD,
            0,
            b"token".to_vec(),
        );
        log.append(AuditKind::Close, 200, 0xCAFE, 0xABCD, 5, vec![]);
    }

    #[test]
    fn fresh_log_verifies() {
        let mut log = AuditLog::new();
        populate(&mut log);
        log.verify().expect("intact chain");
    }

    #[test]
    fn head_advances_on_each_append() {
        let mut log = AuditLog::new();
        let h0 = log.head;
        log.append(AuditKind::SessionEstablished, 1, 1, 1, 0, vec![]);
        assert_ne!(log.head, h0);
        let h1 = log.head;
        log.append(AuditKind::Close, 2, 1, 1, 1, vec![]);
        assert_ne!(log.head, h1);
    }

    #[test]
    fn tampering_detected() {
        let mut log = AuditLog::new();
        populate(&mut log);
        log.entries[1].t_utc_s = 9999;
        // Entry 2 still points at the original entry-1 hash, so the
        // mismatch is detected at index 2.
        let r = log.verify();
        assert!(r.is_err());
    }

    #[test]
    fn truncation_detected() {
        let mut log = AuditLog::new();
        populate(&mut log);
        // Drop the last entry but leave the head pointing at it.
        log.entries.pop();
        let r = log.verify();
        assert_eq!(r.err(), Some(log.entries.len()));
    }

    #[test]
    fn empty_log_verifies() {
        let log = AuditLog::new();
        log.verify().expect("empty is intact");
    }
}
