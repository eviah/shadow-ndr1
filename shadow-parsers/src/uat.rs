//! UAT (Universal Access Transceiver) 978 MHz Decoding
//!
//! Decodes aircraft position and weather reports transmitted on 978 MHz.
//! Used primarily by general aviation (GA) aircraft.
//!
//! References:
//! - RTCA DO-242B (UAT specifications)
//! - FIS-B (Flight Information Service-Broadcast)

use serde::{Deserialize, Serialize};

/// UAT Frame Header
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct UatHeader {
    /// Frame type (0-5)
    pub frame_type: u8,
    /// Application ID (0-8)
    pub app_id: u8,
}

/// Aircraft position and velocity
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct UatAircraftReport {
    /// ICAO24 address (3 bytes)
    pub icao24: u32,
    /// Latitude (degrees)
    pub latitude: f64,
    /// Longitude (degrees)
    pub longitude: f64,
    /// Altitude (feet)
    pub altitude_ft: i32,
    /// Velocity (knots)
    pub velocity_knots: f32,
    /// Vertical rate (feet/minute)
    pub vertical_rate_fpm: i32,
}

/// Ground station report
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct UatGroundReport {
    /// Station location (latitude, longitude)
    pub location: (f64, f64),
    /// Signal strength (dBm)
    pub signal_strength_dbm: i16,
}

/// Flight Information Service-Broadcast (FIS-B) message
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FisbMessage {
    /// Message type ID
    pub type_id: u8,
    /// Product code (weather, NOTAM, etc.)
    pub product_code: u16,
    /// Payload data
    pub payload: Vec<u8>,
}

/// UAT Payload
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum UatPayload {
    /// Aircraft position/velocity report
    AircraftReport(UatAircraftReport),
    /// Ground station report
    GroundStation(UatGroundReport),
    /// Flight Information Service-Broadcast
    Fisb(FisbMessage),
    /// Unknown payload
    Unknown { raw: Vec<u8> },
}

/// Complete UAT frame
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct UatFrame {
    /// Frame header
    pub hdr: UatHeader,
    /// Payload
    pub payload: UatPayload,
}

/// UAT parsing error
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum UatError {
    /// Insufficient data
    InsufficientData,
    /// Invalid frame structure
    InvalidFrame,
    /// Checksum mismatch
    ChecksumMismatch,
    /// Unsupported message type
    UnsupportedType(u8),
}

/// Parse UAT frame from raw bytes
pub fn parse_uat(data: &[u8]) -> Result<UatFrame, UatError> {
    if data.len() < 3 {
        return Err(UatError::InsufficientData);
    }

    // Parse header
    let frame_type = (data[0] >> 5) & 0x07;
    let app_id = data[0] & 0x1F;

    let hdr = UatHeader { frame_type, app_id };

    // Stub: Minimal parsing for compilation
    let payload = UatPayload::Unknown {
        raw: data.to_vec(),
    };

    Ok(UatFrame { hdr, payload })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_uat_minimal() {
        let data = vec![0x00, 0x00, 0x00];
        let frame = parse_uat(&data).unwrap();
        assert_eq!(frame.hdr.frame_type, 0);
    }

    #[test]
    fn test_parse_uat_insufficient_data() {
        let data = vec![0x00];
        let result = parse_uat(&data);
        assert!(matches!(result, Err(UatError::InsufficientData)));
    }

    #[test]
    fn test_uat_frame_serialization() {
        let frame = UatFrame {
            hdr: UatHeader {
                frame_type: 0,
                app_id: 1,
            },
            payload: UatPayload::Unknown { raw: vec![] },
        };

        let json = serde_json::to_string(&frame).unwrap();
        assert!(json.contains("frame_type"));
    }
}
