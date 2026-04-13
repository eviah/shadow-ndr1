//! Threat detection structures for aviation protocols.

use serde::{Deserialize, Serialize};
use crate::common::criticality::AviationCriticality;
use crate::common::timestamp::TimestampNanos;

/// Types of threats detected in aviation networks.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum ThreatType {
    /// ADS‑B spoofing – ghost aircraft or faked positions.
    AdsbSpoofing,
    /// ACARS hijack – unauthorised message injection.
    AcarsHijack,
    /// GPS spoofing – false navigation data.
    GpsSpoofing,
    /// Mode S spoofing – fake squitter or identity.
    ModeSSpoofing,
    /// VDL Mode 2 attack – malicious X.25 frames.
    VdlAttack,
    /// CPDLC injection – false clearances.
    CpdlcInjection,
    /// AeroMACS security violation.
    AeroMacsViolation,
    /// Emergency squawk (7700) – real emergency, not a threat.
    EmergencySquawk,
    /// Hijack squawk (7500) – threat.
    HijackSquawk,
    /// Communication failure (7600) – loss of radio.
    RadioFailure,
    /// Impossible kinematic (speed/altitude beyond physical limits).
    ImpossibleKinematic,
    /// Duplicate ICAO24 with different position.
    DuplicateIcao,
    /// Unauthorised command (e.g., ACARS uplink from unknown source).
    UnauthorisedCommand,
    /// Generic anomaly.
    GenericAnomaly,
    /// Unknown threat.
    Unknown,
}

/// A detected threat with metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Threat {
    /// Type of threat.
    pub threat_type: ThreatType,
    /// Criticality level.
    pub criticality: AviationCriticality,
    /// Human‑readable description.
    pub description: String,
    /// Confidence score (0.0 – 1.0).
    pub confidence: f32,
    /// Source identifier (ICAO24, callsign, IP, etc.).
    pub source: Option<String>,
    /// Timestamp when detected.
    pub detected_at: TimestampNanos,
}

impl Threat {
    /// Create a new threat with current timestamp.
    pub fn new(
        threat_type: ThreatType,
        criticality: AviationCriticality,
        description: impl Into<String>,
        confidence: f32,
        source: Option<String>,
    ) -> Self {
        Self {
            threat_type,
            criticality,
            description: description.into(),
            confidence,
            source,
            detected_at: TimestampNanos::now(),
        }
    }

    /// Builder pattern for more ergonomic construction.
    pub fn builder() -> ThreatBuilder {
        ThreatBuilder::default()
    }

    /// Returns 	rue if this threat is considered dangerous (Emergency or SystemFailure).
    pub fn is_dangerous(&self) -> bool {
        matches!(
            self.criticality,
            AviationCriticality::Emergency | AviationCriticality::SystemFailure
        )
    }
}

/// Builder for Threat.
#[derive(Default)]
pub struct ThreatBuilder {
    threat_type: Option<ThreatType>,
    criticality: Option<AviationCriticality>,
    description: Option<String>,
    confidence: Option<f32>,
    source: Option<String>,
}

impl ThreatBuilder {
    pub fn threat_type(mut self, t: ThreatType) -> Self {
        self.threat_type = Some(t);
        self
    }

    pub fn criticality(mut self, c: AviationCriticality) -> Self {
        self.criticality = Some(c);
        self
    }

    pub fn description(mut self, d: impl Into<String>) -> Self {
        self.description = Some(d.into());
        self
    }

    pub fn confidence(mut self, c: f32) -> Self {
        self.confidence = Some(c);
        self
    }

    pub fn source(mut self, s: impl Into<String>) -> Self {
        self.source = Some(s.into());
        self
    }

    pub fn build(self) -> Threat {
        Threat {
            threat_type: self.threat_type.unwrap_or(ThreatType::Unknown),
            criticality: self.criticality.unwrap_or(AviationCriticality::Normal),
            description: self.description.unwrap_or_default(),
            confidence: self.confidence.unwrap_or(0.0),
            source: self.source,
            detected_at: TimestampNanos::now(),
        }
    }
}
