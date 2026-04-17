//! Golay(24,12) Error Correction Code for Mode S
//!
//! Implements Golay(24,12) systematic code for Mode S frame error detection
//! and single-bit error correction. Mode S frames use a 24-bit parity check
//! that can correct 1-bit errors and detect 2-bit errors.
//!
//! Used to recover mangled ADS-B and Mode C replies that have single-bit corruption.

use std::ops::BitXor;

/// Generator matrix for Golay(24,12) - precomputed
/// Each row is a generator polynomial for one information bit
const GOLAY_GENERATOR: &[[u8; 3]] = &[
    [0xFF, 0xF8, 0x00], // bit 0
    [0xFF, 0xF4, 0x00], // bit 1
    [0xFF, 0xF2, 0x00], // bit 2
    [0xFF, 0xF1, 0x00], // bit 3
    [0x7F, 0xF8, 0x80], // bit 4
    [0xBF, 0xF8, 0x40], // bit 5
    [0xDF, 0xF8, 0x20], // bit 6
    [0xEF, 0xF8, 0x10], // bit 7
    [0xF7, 0xF8, 0x08], // bit 8
    [0xFB, 0xF8, 0x04], // bit 9
    [0xFD, 0xF8, 0x02], // bit 10
    [0xFE, 0xF8, 0x01], // bit 11
];

/// Parity check matrix for error detection/correction
const GOLAY_PARITY: &[[u8; 3]] = &[
    [0x00, 0x00, 0x01], // syndrome bit 0
    [0x00, 0x00, 0x02], // syndrome bit 1
    [0x00, 0x00, 0x04], // syndrome bit 2
    [0x00, 0x00, 0x08], // syndrome bit 3
    [0x00, 0x00, 0x10], // syndrome bit 4
    [0x00, 0x00, 0x20], // syndrome bit 5
    [0x00, 0x00, 0x40], // syndrome bit 6
    [0x00, 0x00, 0x80], // syndrome bit 7
    [0x00, 0x01, 0x00], // syndrome bit 8
    [0x00, 0x02, 0x00], // syndrome bit 9
    [0x00, 0x04, 0x00], // syndrome bit 10
    [0x00, 0x08, 0x00], // syndrome bit 11
];

/// Represents a Golay(24,12) codeword (24 bits total)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GolayCodeword {
    /// 24-bit value (3 bytes)
    pub bits: u32,
}

/// Result of Golay decoding
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GolayResult {
    /// No errors detected
    Ok,
    /// Single-bit error detected and corrected at position
    Corrected(usize),
    /// Uncorrectable error (2+ bits)
    UnrecoverableError,
}

impl GolayCodeword {
    /// Create a codeword from 24 bits
    pub fn from_bits(bits: u32) -> Self {
        GolayCodeword {
            bits: bits & 0xFF_FFFF, // Keep only 24 bits
        }
    }

    /// Create from 3 bytes (big-endian)
    pub fn from_bytes(b0: u8, b1: u8, b2: u8) -> Self {
        GolayCodeword {
            bits: ((b0 as u32) << 16) | ((b1 as u32) << 8) | (b2 as u32),
        }
    }

    /// Extract as 3 bytes (big-endian)
    pub fn to_bytes(&self) -> (u8, u8, u8) {
        (
            ((self.bits >> 16) & 0xFF) as u8,
            ((self.bits >> 8) & 0xFF) as u8,
            (self.bits & 0xFF) as u8,
        )
    }

    /// Encode 12 information bits into 24-bit Golay codeword
    pub fn encode(info: u16) -> Self {
        let info = (info & 0xFFF) as u32; // Keep only 12 bits

        // Generate parity bits by multiplying with generator matrix
        let mut parity = 0u32;
        for i in 0..12 {
            if (info & (1 << i)) != 0 {
                let row = GOLAY_GENERATOR[i];
                let row_val = ((row[0] as u32) << 16) | ((row[1] as u32) << 8) | (row[2] as u32);
                parity ^= row_val;
            }
        }

        // Codeword = [info bits (12)] [parity bits (12)]
        GolayCodeword {
            bits: (info << 12) | (parity & 0xFFF),
        }
    }

    /// Decode and correct single-bit errors
    pub fn decode(&self) -> (u16, GolayResult) {
        let codeword = self.bits;

        // Calculate syndrome (parity check)
        let mut syndrome = 0u32;
        for i in 0..12 {
            let row = GOLAY_PARITY[i];
            let row_val = ((row[0] as u32) << 16) | ((row[1] as u32) << 8) | (row[2] as u32);
            if (codeword & row_val).count_ones() % 2 == 1 {
                syndrome |= 1 << i;
            }
        }

        if syndrome == 0 {
            // No errors
            let info = (codeword >> 12) & 0xFFF;
            return (info as u16, GolayResult::Ok);
        }

        // Syndrome != 0: error detected
        // Find error position by checking if syndrome matches a single-bit pattern
        let error_weight = syndrome.count_ones();

        if error_weight == 1 {
            // Single-bit error in parity part
            let error_pos = syndrome.trailing_zeros() as usize;
            let corrected = GolayCodeword {
                bits: codeword ^ (1 << error_pos),
            };
            let info = (corrected.bits >> 12) & 0xFFF;
            return (info as u16, GolayResult::Corrected(error_pos));
        }

        // Try to find error in information bits by syndrome lookup
        for error_bit in 0..12 {
            // Flip information bit and recalculate syndrome
            let test_codeword = codeword ^ (1 << (12 + error_bit));
            let mut test_syndrome = 0u32;
            for i in 0..12 {
                let row = GOLAY_PARITY[i];
                let row_val = ((row[0] as u32) << 16) | ((row[1] as u32) << 8) | (row[2] as u32);
                if (test_codeword & row_val).count_ones() % 2 == 1 {
                    test_syndrome |= 1 << i;
                }
            }

            if test_syndrome == 0 {
                // Found error in information bit
                let corrected = GolayCodeword {
                    bits: codeword ^ (1 << (12 + error_bit)),
                };
                let info = (corrected.bits >> 12) & 0xFFF;
                return (info as u16, GolayResult::Corrected(12 + error_bit));
            }
        }

        // Uncorrectable error (2+ bits)
        let info = (codeword >> 12) & 0xFFF;
        (info as u16, GolayResult::UnrecoverableError)
    }

    /// Verify checksum (returns true if valid, false if error)
    pub fn verify(&self) -> bool {
        let (_, result) = self.decode();
        result == GolayResult::Ok || matches!(result, GolayResult::Corrected(_))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_decode() {
        let info = 0x123u16;
        let codeword = GolayCodeword::encode(info);
        let (decoded, result) = codeword.decode();

        assert_eq!(decoded, info);
        assert_eq!(result, GolayResult::Ok);
    }

    #[test]
    fn test_single_bit_error_correction() {
        let info = 0x456u16;
        let mut codeword = GolayCodeword::encode(info);

        // Introduce single-bit error
        codeword.bits ^= 0x000001; // Flip bit 0

        let (decoded, result) = codeword.decode();
        assert_eq!(decoded, info);
        assert!(matches!(result, GolayResult::Corrected(_)));
    }

    #[test]
    fn test_error_detection() {
        let info = 0xABCu16;
        let mut codeword = GolayCodeword::encode(info);

        // Introduce two-bit error
        codeword.bits ^= 0x000003; // Flip bits 0 and 1

        let (_, result) = codeword.decode();
        assert_eq!(result, GolayResult::UnrecoverableError);
    }

    #[test]
    fn test_bytes_roundtrip() {
        let codeword = GolayCodeword::from_bytes(0xAB, 0xCD, 0xEF);
        let (b0, b1, b2) = codeword.to_bytes();

        assert_eq!(b0, 0xAB);
        assert_eq!(b1, 0xCD);
        assert_eq!(b2, 0xEF);
    }
}
