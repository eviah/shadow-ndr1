//! ICAO Aircraft Registration Validator
//!
//! Validates aircraft ICAO24 addresses against known registrations.
//! Detects spoofed/unknown aircraft and flags suspicious registrations.

use std::collections::HashMap;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IcaoRegistration {
    pub icao24: u32,
    pub callsign: String,
    pub aircraft_type: String,
    pub operator: String,
    pub registration: String,
    pub confidence: f32,
}

#[derive(Debug, Clone)]
pub enum IcaoValidationResult {
    /// Aircraft is known and matches expected profile
    Valid(IcaoRegistration),
    /// Aircraft ICAO24 exists but data mismatch
    MismatchedCallsign { registered: String, reported: String },
    /// ICAO24 is completely unknown
    Unknown(u32),
    /// ICAO24 format is invalid
    InvalidFormat(u32),
}

/// High-performance ICAO registration validator
pub struct IcaoValidator {
    /// ICAO24 → Registration mapping
    registry: HashMap<u32, IcaoRegistration>,
    /// Known spoofed/reserved ranges
    reserved_ranges: Vec<(u32, u32)>,
    stats: ValidatorStats,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct ValidatorStats {
    pub total_queries: u64,
    pub valid_count: u64,
    pub unknown_count: u64,
    pub mismatch_count: u64,
    pub invalid_format_count: u64,
}

impl IcaoValidator {
    /// Create a new ICAO validator with empty registry
    pub fn new() -> Self {
        IcaoValidator {
            registry: HashMap::new(),
            reserved_ranges: vec![
                // Military/Reserved ICAO ranges (common spoofing sources)
                (0x000000, 0x000FFF),  // Test frames
                (0xFF0000, 0xFFFFFF),  // Reserved range
            ],
            stats: ValidatorStats::default(),
        }
    }

    /// Add aircraft to registry
    pub fn register_aircraft(&mut self, reg: IcaoRegistration) {
        self.registry.insert(reg.icao24, reg);
    }

    /// Batch load registrations
    pub fn load_registry(&mut self, registrations: Vec<IcaoRegistration>) {
        for reg in registrations {
            self.registry.insert(reg.icao24, reg);
        }
    }

    /// Validate aircraft ICAO24 and optional callsign
    pub fn validate(&mut self, icao24: u32, reported_callsign: Option<&str>) -> IcaoValidationResult {
        self.stats.total_queries += 1;

        // Check format validity
        if !is_valid_icao24_format(icao24) {
            self.stats.invalid_format_count += 1;
            return IcaoValidationResult::InvalidFormat(icao24);
        }

        // Check if in reserved range
        if self.is_reserved(icao24) {
            self.stats.unknown_count += 1;
            return IcaoValidationResult::Unknown(icao24);
        }

        // Check registry
        if let Some(reg) = self.registry.get(&icao24) {
            if let Some(callsign) = reported_callsign {
                if callsign.trim() != reg.callsign.trim() && !callsign.is_empty() {
                    self.stats.mismatch_count += 1;
                    return IcaoValidationResult::MismatchedCallsign {
                        registered: reg.callsign.clone(),
                        reported: callsign.to_string(),
                    };
                }
            }
            self.stats.valid_count += 1;
            return IcaoValidationResult::Valid(reg.clone());
        }

        self.stats.unknown_count += 1;
        IcaoValidationResult::Unknown(icao24)
    }

    /// Check if ICAO24 is in reserved range
    fn is_reserved(&self, icao24: u32) -> bool {
        self.reserved_ranges.iter().any(|(start, end)| icao24 >= *start && icao24 <= *end)
    }

    /// Get validator statistics
    pub fn get_stats(&self) -> ValidatorStats {
        self.stats.clone()
    }

    /// Calculate spoofing risk score (0.0 = safe, 1.0 = highly suspicious)
    pub fn calculate_spoofing_risk(&self, icao24: u32, callsign: Option<&str>) -> f32 {
        let mut risk: f32 = 0.0;

        // Risk factor 1: Unknown ICAO
        if !self.registry.contains_key(&icao24) {
            risk += 0.4;
        }

        // Risk factor 2: Mismatched callsign
        if let Some(cs) = callsign {
            if let Some(reg) = self.registry.get(&icao24) {
                if cs.trim() != reg.callsign.trim() {
                    risk += 0.3;
                }
            }
        }

        // Risk factor 3: Reserved range
        if self.is_reserved(icao24) {
            risk += 0.3;
        }

        risk.min(1.0)
    }
}

impl Default for IcaoValidator {
    fn default() -> Self {
        Self::new()
    }
}

/// Validate ICAO24 format (24-bit address)
fn is_valid_icao24_format(icao24: u32) -> bool {
    // ICAO24 should be within 24-bit range
    icao24 <= 0xFFFFFF
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_icao_validation() {
        let mut validator = IcaoValidator::new();

        // Register a known aircraft
        validator.register_aircraft(IcaoRegistration {
            icao24: 0x3C5EF8,
            callsign: "BA9".to_string(),
            aircraft_type: "Boeing 777".to_string(),
            operator: "British Airways".to_string(),
            registration: "G-STBZ".to_string(),
            confidence: 0.95,
        });

        // Test valid registration
        match validator.validate(0x3C5EF8, Some("BA9")) {
            IcaoValidationResult::Valid(reg) => assert_eq!(reg.callsign, "BA9"),
            _ => panic!("Expected valid result"),
        }

        // Test unknown ICAO
        match validator.validate(0x123456, None) {
            IcaoValidationResult::Unknown(_) => (),
            _ => panic!("Expected unknown result"),
        }

        // Test mismatched callsign
        match validator.validate(0x3C5EF8, Some("AA100")) {
            IcaoValidationResult::MismatchedCallsign { .. } => (),
            _ => panic!("Expected mismatch result"),
        }
    }

    #[test]
    fn test_spoofing_risk() {
        let validator = IcaoValidator::new();
        let risk = validator.calculate_spoofing_risk(0xFFFFFF, None);
        assert!(risk > 0.5, "Reserved range should have high risk");
    }
}
