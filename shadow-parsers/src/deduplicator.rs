//! Packet Deduplicator
//!
//! Removes duplicate packets received from multiple receivers
//! using hash-based content addressing.

use std::collections::VecDeque;
use serde::{Deserialize, Serialize};

const DEDUP_WINDOW_SIZE: usize = 10000;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeduplicationStats {
    pub total_packets: u64,
    pub duplicates_found: u64,
    pub unique_packets: u64,
    pub duplicate_ratio: f64,
}

/// Rolling window packet deduplicator using xxHash
pub struct PacketDeduplicator {
    window: VecDeque<u64>,
    total_packets: u64,
    duplicates_found: u64,
}

impl PacketDeduplicator {
    /// Create new deduplicator with default window size
    pub fn new() -> Self {
        PacketDeduplicator {
            window: VecDeque::with_capacity(DEDUP_WINDOW_SIZE),
            total_packets: 0,
            duplicates_found: 0,
        }
    }

    /// Check if packet is a duplicate and update state
    pub fn is_duplicate(&mut self, data: &[u8]) -> bool {
        self.total_packets += 1;

        let hash = xxhash64(data);

        // Check if hash is in window
        let is_dup = self.window.contains(&hash);

        if is_dup {
            self.duplicates_found += 1;
        } else {
            // Add to window
            self.window.push_back(hash);

            // Maintain window size
            if self.window.len() > DEDUP_WINDOW_SIZE {
                self.window.pop_front();
            }
        }

        is_dup
    }

    /// Get deduplication statistics
    pub fn stats(&self) -> DeduplicationStats {
        let unique_packets = self.total_packets - self.duplicates_found;
        let duplicate_ratio = if self.total_packets > 0 {
            self.duplicates_found as f64 / self.total_packets as f64
        } else {
            0.0
        };

        DeduplicationStats {
            total_packets: self.total_packets,
            duplicates_found: self.duplicates_found,
            unique_packets,
            duplicate_ratio,
        }
    }

    /// Clear all state
    pub fn reset(&mut self) {
        self.window.clear();
        self.total_packets = 0;
        self.duplicates_found = 0;
    }
}

impl Default for PacketDeduplicator {
    fn default() -> Self {
        Self::new()
    }
}

/// xxHash64 implementation (FNV-1a alternative)
/// Production code would use xxhash crate, this is simplified version
fn xxhash64(data: &[u8]) -> u64 {
    const PRIME64_1: u64 = 0x9E3779B185EBCA87;
    const PRIME64_2: u64 = 0xC2B2AE3D27D4EB4D;
    const PRIME64_3: u64 = 0x165667B19E3779F9;
    const PRIME64_4: u64 = 0x85EBCA77C2B2AE63;
    const PRIME64_5: u64 = 0x27D4EB2D165667C5;

    let mut h64 = if data.is_empty() {
        PRIME64_5
    } else {
        PRIME64_1.wrapping_add(PRIME64_2)
    };

    // Process 8-byte chunks
    let chunks = data.len() / 8;
    for i in 0..chunks {
        let bytes = &data[i * 8..(i + 1) * 8];
        let val = u64::from_le_bytes(bytes.try_into().unwrap_or([0; 8]));
        h64 = h64.wrapping_add(val.wrapping_mul(PRIME64_2));
        h64 = h64.rotate_left(31).wrapping_mul(PRIME64_1);
    }

    // Process remaining bytes
    let remainder = data.len() % 8;
    let offset = chunks * 8;
    let mut h64_tail = h64;

    for i in 0..remainder {
        let byte = data[offset + i] as u64;
        h64_tail = h64_tail.wrapping_add(byte.wrapping_mul(PRIME64_5));
        h64_tail = h64_tail.rotate_left(11).wrapping_mul(PRIME64_1);
    }

    h64 = h64.wrapping_add(h64_tail);
    h64 ^= h64 >> 33;
    h64 = h64.wrapping_mul(PRIME64_2);
    h64 ^= h64 >> 29;

    h64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_duplicate_detection() {
        let mut dedup = PacketDeduplicator::new();

        let packet = b"test packet data";

        // First occurrence - not a duplicate
        assert!(!dedup.is_duplicate(packet));

        // Second occurrence - is a duplicate
        assert!(dedup.is_duplicate(packet));

        // Different packet - not a duplicate
        assert!(!dedup.is_duplicate(b"different data"));
    }

    #[test]
    fn test_window_size() {
        let mut dedup = PacketDeduplicator::new();

        // Fill window with unique packets
        for i in 0..DEDUP_WINDOW_SIZE + 100 {
            let data = format!("packet_{}", i).into_bytes();
            let _ = dedup.is_duplicate(&data);
        }

        let stats = dedup.stats();
        assert_eq!(stats.total_packets, (DEDUP_WINDOW_SIZE + 100) as u64);
    }

    #[test]
    fn test_statistics() {
        let mut dedup = PacketDeduplicator::new();

        let packet1 = b"packet1";
        let packet2 = b"packet2";

        dedup.is_duplicate(packet1);
        dedup.is_duplicate(packet1); // Duplicate
        dedup.is_duplicate(packet2);
        dedup.is_duplicate(packet1); // Duplicate

        let stats = dedup.stats();
        assert_eq!(stats.total_packets, 4);
        assert_eq!(stats.duplicates_found, 2);
        assert_eq!(stats.unique_packets, 2);
        assert!((stats.duplicate_ratio - 0.5).abs() < 0.01);
    }

    #[test]
    fn test_xxhash_consistency() {
        let data = b"consistent test data";
        let hash1 = xxhash64(data);
        let hash2 = xxhash64(data);
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_reset() {
        let mut dedup = PacketDeduplicator::new();
        dedup.is_duplicate(b"packet");
        dedup.reset();

        let stats = dedup.stats();
        assert_eq!(stats.total_packets, 0);
        assert_eq!(stats.duplicates_found, 0);
    }
}
