//! TIS-B (Traffic Information Service-Broadcast) Parsing
//!
//! TIS-B is ATC rebroadcast of traffic information on 1090 MHz ES channel.
//! Contains aircraft positions reported by other sensors (ADS-B, MLAT, radar).
//!
//! References:
//! - ICAO Annex 10 Chapter 3.1.2.6.5.4

use serde::{Deserialize, Serialize};

/// TIS-B management header
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TisbManagementHeader {
    /// Message type (0-31)
    pub msg_type: u8,
    /// ICAO address of serving ground station
    pub serving_station: u32,
}

/// TIS-B source type
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum TisbSource {
    /// From ADS-B transmission
    AdsB,
    /// From surface surveillance (radar/ground)
    Surface,
    /// From ADS-R (forwarded ADS-B)
    AdsR,
    /// From TIS-B rebroadcast
    TisB,
    /// Unknown source
    Unknown,
}

/// Complete TIS-B frame (reuses AdsbFrame for payload)
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TisbFrame {
    /// Management header
    pub management_header: TisbManagementHeader,
    /// Source of the traffic information
    pub source_type: TisbSource,
    /// Raw payload (typically an ADS-B-like structure)
    pub payload_raw: Vec<u8>,
    /// ICAO of the aircraft being served TIS-B about
    pub icao24_served: u32,
}

/// TIS-B parsing error
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum TisbError {
    /// Insufficient data
    InsufficientData,
    /// Invalid management header
    InvalidHeader,
    /// Checksum mismatch
    ChecksumMismatch,
}

/// Parse TIS-B frame from raw bytes
pub fn parse_tisb(data: &[u8]) -> Result<TisbFrame, TisbError> {
    if data.len() < 7 {
        return Err(TisbError::InsufficientData);
    }

    // Stub: Minimal parsing
    let msg_type = data[0] & 0x1F;
    let serving_station = u32::from_be_bytes([0, data[1], data[2], data[3]]);

    let management_header = TisbManagementHeader {
        msg_type,
        serving_station,
    };

    let icao24_served = if data.len() >= 10 {
        u32::from_be_bytes([0, data[7], data[8], data[9]])
    } else {
        0
    };

    Ok(TisbFrame {
        management_header,
        source_type: TisbSource::Unknown,
        payload_raw: data[6..].to_vec(),
        icao24_served,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_tisb_minimal() {
        let data = vec![0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        let frame = parse_tisb(&data).unwrap();
        assert_eq!(frame.management_header.msg_type, 0);
    }

    #[test]
    fn test_parse_tisb_insufficient() {
        let data = vec![0x00, 0x00];
        let result = parse_tisb(&data);
        assert!(matches!(result, Err(TisbError::InsufficientData)));
    }

    #[test]
    fn test_tisb_source_types() {
        let source = TisbSource::AdsB;
        assert_eq!(source, TisbSource::AdsB);
    }

    #[test]
    fn test_tisb_frame_serialization() {
        let frame = TisbFrame {
            management_header: TisbManagementHeader {
                msg_type: 1,
                serving_station: 0x123456,
            },
            source_type: TisbSource::Surface,
            payload_raw: vec![],
            icao24_served: 0xABCDEF,
        };

        let json = serde_json::to_string(&frame).unwrap();
        assert!(json.contains("msg_type"));
    }
}
