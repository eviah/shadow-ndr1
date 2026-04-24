//! Shadow NDR – Aviation Protocol Parsers Suite
//!
//! This crate provides high‑performance, memory‑safe parsers for aviation
//! communication protocols used in the Shadow NDR platform. It includes
//! complete implementations of:
//!
//! - **ADS‑B** (Mode S Extended Squitter)
//! - **ACARS** (Aircraft Communications Addressing and Reporting System)
//! - **Mode S** (short and long squitters)
//! - **VDL Mode 2** (VHF Data Link)
//! - **CPDLC** (Controller–Pilot Data Link Communications)
//! - **AeroMACS** (Aeronautical Mobile Airport Communications System)
//! - **IEC 60870‑5‑104** (telecontrol, extended for airport ground systems)
//!
//! # Features
//! - Zero‑copy parsing with `nom`
//! - Streaming parsers with buffer pooling
//! - Built‑in threat detection (spoofing, hijack, jamming, kinematic anomalies)
//! - Aviation criticality levels (Normal, Warning, Emergency, SystemFailure)
//! - Serialization to JSON / bincode
//! - Comprehensive tests and benchmarks
//! - Feature flags for selective compilation
//!
//! # Example
//! ```
//! use shadow_parsers::prelude::*;
//!
//! // Parse an ADS‑B frame
//! let raw = &[0x8D, 0x76, 0x1B, 0x2A, 0x58, 0x99, 0x20, 0x2E, 0x23, 0x60, 0x52, 0x00, 0x00, 0x00];
//! let frame = parse_adsb(raw).unwrap();
//! println!("{}", frame);
//! ```

#![warn(missing_docs)]
#![deny(rustdoc::broken_intra_doc_links)]

// =============================================================================
// Protocol modules (feature‑gated)
// =============================================================================

#[cfg(feature = "adsb")]
pub mod adsb;
#[cfg(feature = "acars")]
pub mod acars;
#[cfg(feature = "mode_s")]
pub mod mode_s;
#[cfg(feature = "vdl")]
pub mod vdl;
#[cfg(feature = "cpdlc")]
pub mod cpdlc;
#[cfg(feature = "aeromacs")]
pub mod aeromacs;
#[cfg(feature = "iec104")]
pub mod iec104;

// =============================================================================
// World-class upgrade modules (feature‑gated)
// =============================================================================

#[cfg(feature = "golay")]
pub mod golay;
#[cfg(feature = "mlat")]
pub mod mlat;
#[cfg(feature = "signal")]
pub mod signal_analysis;
#[cfg(feature = "spoofing")]
pub mod spoofing_detector;
#[cfg(feature = "geofencing")]
pub mod geofencing;
#[cfg(feature = "uat")]
pub mod uat;
#[cfg(feature = "tisb")]
pub mod tisb;

// Additional threat detection modules (world-class upgrades)
#[cfg(feature = "icao_validator")]
pub mod icao_validator;
#[cfg(feature = "burst")]
pub mod burst_detector;
#[cfg(feature = "baseline")]
pub mod baseline_scorer;
#[cfg(feature = "consensus")]
pub mod mesh_consensus;
#[cfg(feature = "correlation")]
pub mod threat_correlation;
#[cfg(feature = "modulation")]
pub mod modulation;
#[cfg(feature = "external_validation")]
pub mod external_validation;
#[cfg(feature = "deduplicator")]
pub mod deduplicator;

// =============================================================================
// Common infrastructure (always present)
// =============================================================================

pub mod common;
pub mod kafka;
pub mod physics;

// Re‑export common types for convenience
pub use common::criticality::AviationCriticality;
pub use common::threat::{Threat, ThreatType};
pub use common::streaming::StreamingParser;
pub use common::pool::{BufferPool, ParseError};
pub use common::timestamp::TimestampNanos;

// =============================================================================
// Version information
// =============================================================================

/// Crate version (from Cargo.toml)
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
/// Crate authors (from Cargo.toml)
pub const AUTHORS: &str = env!("CARGO_PKG_AUTHORS");
/// Crate description (from Cargo.toml)
pub const DESCRIPTION: &str = env!("CARGO_PKG_DESCRIPTION");
/// Repository URL (from Cargo.toml)
pub const REPOSITORY: &str = env!("CARGO_PKG_REPOSITORY");

// =============================================================================
// Prelude – one‑stop import for common types
// =============================================================================

/// The prelude module collects all commonly used types and functions.
/// Import this to get everything you need for working with the library.
pub mod prelude {
    // Common types (always available)
    pub use crate::common::criticality::AviationCriticality;
    pub use crate::common::threat::{Threat, ThreatType};
    pub use crate::common::streaming::StreamingParser;
    pub use crate::common::pool::{BufferPool, ParseError};
    pub use crate::common::timestamp::TimestampNanos;

    // Re‑export parsers and their frames (conditionally)
    #[cfg(feature = "adsb")]
    pub use crate::adsb::{AdsbFrame, parse_adsb};
    #[cfg(feature = "acars")]
    pub use crate::acars::{AcarsFrame, parse_acars};
    #[cfg(feature = "mode_s")]
    pub use crate::mode_s::{ModeSFrame, parse_mode_s};
    #[cfg(feature = "vdl")]
    pub use crate::vdl::{VdlFrame, parse_vdl};
    #[cfg(feature = "cpdlc")]
    pub use crate::cpdlc::{CpdlcFrame, parse_cpdlc};
    #[cfg(feature = "aeromacs")]
    pub use crate::aeromacs::{AeroMacsFrame, parse_aeromacs};
    #[cfg(feature = "iec104")]
    pub use crate::iec104::{
        parse_iec104, parse_enriched, Iec104Frame, EnrichedFrame,
        Apci, UCmd, Cot, Quality, CriticalityLevel, InformationAddress,
        InfoVal, InfoObj, Asdu,
        // Re‑export streaming parser as Iec104StreamingParser to avoid name clash
        StreamingParser as Iec104StreamingParser,
        ParsePool,
    };

    // World-class upgrade modules
    #[cfg(feature = "golay")]
    pub use crate::golay::{GolayCodeword, GolayResult};
    #[cfg(feature = "mlat")]
    pub use crate::mlat::{MlatEngine, MlatSensor, MlatSolution, ToaMeasurement};
    #[cfg(feature = "signal")]
    pub use crate::signal_analysis::{RssiTracker, RssiAnomaly};
    #[cfg(feature = "spoofing")]
    pub use crate::spoofing_detector::{SpoofingDetector, SpoofingIndicator, RfFingerprint};
    #[cfg(feature = "geofencing")]
    pub use crate::geofencing::{GeofenceEngine, GeofenceZone, ZoneType};
    #[cfg(feature = "uat")]
    pub use crate::uat::{UatFrame, parse_uat};
    #[cfg(feature = "tisb")]
    pub use crate::tisb::{TisbFrame, parse_tisb};

    // Advanced threat detection modules
    #[cfg(feature = "icao_validator")]
    pub use crate::icao_validator::{IcaoValidator, IcaoRegistration, IcaoValidationResult};
    #[cfg(feature = "burst")]
    pub use crate::burst_detector::{BurstDetector, BurstIndicator, AircraftTrack};
    #[cfg(feature = "baseline")]
    pub use crate::baseline_scorer::{BaselineScorer, FlightProfile, BaselineDeviation};
    #[cfg(feature = "consensus")]
    pub use crate::mesh_consensus::{MeshConsensus, SensorReport, ConsensusSolution};
    #[cfg(feature = "correlation")]
    pub use crate::threat_correlation::{ThreatCorrelator, ThreatEvent, ThreatEventType, CorrelationCluster};
    #[cfg(feature = "modulation")]
    pub use crate::modulation::{ModulationSample, ModulationQuality, analyze_modulation};
    #[cfg(feature = "external_validation")]
    pub use crate::external_validation::{ExternalValidator, ExternalAircraftState, PositionDiscrepancy, CallsignMatch};
    #[cfg(feature = "deduplicator")]
    pub use crate::deduplicator::{PacketDeduplicator, DeduplicationStats};
}

// =============================================================================
// Aviation utilities
// =============================================================================

/// Utilities for interpreting IEC 104 frames in an aviation (ground-infra) context.
/// Used for airport SCADA, radar perimeters, runway lighting, and ATC I/O.
#[cfg(feature = "iec104")]
pub mod aviation {
    use crate::iec104::{Iec104Frame, InfoVal, CriticalityLevel};

    /// Represents an aviation asset identifier derived from IEC104 common address.
    #[derive(Debug, Clone, PartialEq, Eq, Hash)]
    pub enum AircraftId {
        /// Aircraft (mainline / passenger).
        Aircraft(u16),
        /// Apron / ground vehicle.
        Ground(u16),
        /// ATC / radar / tower equipment.
        Atc(u16),
        /// Unknown kind.
        Unknown(u16),
    }

    impl std::fmt::Display for AircraftId {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            match self {
                AircraftId::Aircraft(id) => write!(f, "AIRCRAFT-{}", id),
                AircraftId::Ground(id) => write!(f, "GROUND-{}", id),
                AircraftId::Atc(id) => write!(f, "ATC-{}", id),
                AircraftId::Unknown(id) => write!(f, "UNKNOWN-{}", id),
            }
        }
    }

    /// Emergency qualifier constant (0x7F).
    pub const EMERGENCY_QUALIFIER: u8 = 0x7F;

    /// Check if a parsed IEC104 frame contains a safety‑critical command.
    pub fn is_safety_critical(frame: &Iec104Frame) -> bool {
        if let Some(asdu) = &frame.asdu {
            // Aviation ground‑infra emergency types (private range)
            if asdu.type_id == 105 || asdu.type_id == 120 {
                return true;
            }

            for obj in &asdu.objects {
                for val in &obj.values {
                    match val {
                        InfoVal::SingleCommand(_, qual, _) if *qual == EMERGENCY_QUALIFIER => return true,
                        InfoVal::DoubleCommand(val, qual, _)
                            if *qual == EMERGENCY_QUALIFIER && (*val == 1 || *val == 2) =>
                        {
                            return true;
                        }
                        InfoVal::SetpointNormalized(_, qual, _) if *qual == EMERGENCY_QUALIFIER => return true,
                        InfoVal::SetpointScaled(_, qual, _) if *qual == EMERGENCY_QUALIFIER => return true,
                        InfoVal::SetpointFloat(_, qual, _) if *qual == EMERGENCY_QUALIFIER => return true,
                        _ => {}
                    }
                }
            }
        }
        false
    }

    /// Check if a command requires explicit operator confirmation.
    pub fn requires_confirmation(frame: &Iec104Frame) -> bool {
        if let Some(asdu) = &frame.asdu {
            for obj in &asdu.objects {
                for val in &obj.values {
                    match val {
                        InfoVal::SingleCommand(_, _, select) => if *select { return true; }
                        InfoVal::DoubleCommand(_, _, select) => if *select { return true; }
                        InfoVal::SetpointNormalized(_, _, select) => if *select { return true; }
                        InfoVal::SetpointScaled(_, _, select) => if *select { return true; }
                        InfoVal::SetpointFloat(_, _, select) => if *select { return true; }
                        _ => {}
                    }
                }
            }
        }
        false
    }

    /// Get aviation asset identifier from common address (simplified mapping).
    pub fn aircraft_id_from_ca(ca: u16) -> AircraftId {
        match ca {
            0x0001..=0x0010 => AircraftId::Aircraft(ca),
            0x1000..=0x1010 => AircraftId::Ground(ca - 0x0FFF),
            0x2001..=0x2010 => AircraftId::Atc(ca - 0x2000),
            _ => AircraftId::Unknown(ca),
        }
    }

    /// Convert criticality level to a string suitable for UI.
    pub fn severity_as_str(level: CriticalityLevel) -> &'static str {
        match level {
            CriticalityLevel::Normal => "INFO",
            CriticalityLevel::High => "HIGH",
            CriticalityLevel::Critical => "CRITICAL",
            CriticalityLevel::SystemFault => "FAULT",
        }
    }
}

// =============================================================================
// Performance benchmarks (optional – only when bench feature is enabled)
// =============================================================================

/// Benchmark modules (only compiled with the `bench` feature).
#[cfg(all(feature = "bench", feature = "iec104"))]
pub mod benches {
    pub use crate::iec104::bench as iec104_bench;
    
    #[cfg(feature = "adsb")]
    pub use crate::adsb::bench as adsb_bench;
    #[cfg(feature = "acars")]
    pub use crate::acars::bench as acars_bench;
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_version_defined() {
        assert!(!VERSION.is_empty());
        assert!(!AUTHORS.is_empty());
        assert!(!DESCRIPTION.is_empty());
    }

    #[test]
    fn test_prelude_imports() {
        use prelude::*;
        // Just verify that the prelude imports work
        #[cfg(feature = "adsb")]
        let _ = parse_adsb;
        #[cfg(feature = "iec104")]
        let _ = parse_iec104;
    }

    #[cfg(feature = "iec104")]
    #[test]
    fn test_aviation_utils() {
        use crate::iec104::*;

        let normal_frame = Iec104Frame {
            apci: Apci::S { recv: 0 },
            asdu: None,
        };
        assert!(!aviation::is_safety_critical(&normal_frame));

        match aviation::aircraft_id_from_ca(0x0001) {
            aviation::AircraftId::Aircraft(1) => (),
            _ => panic!("wrong aircraft id"),
        }
    }
}
