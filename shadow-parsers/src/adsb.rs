//! ADS-B parser module
use crate::common::criticality::AviationCriticality;
use crate::common::threat::Threat;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdsbFrame {
    pub icao24: u32,
    pub callsign: Option<String>,
    pub emergency: bool,
}

pub fn parse_adsb(data: &[u8]) -> Result<AdsbFrame, crate::common::pool::ParseError> {
    if data.len() < 14 {
        return Err(crate::common::pool::ParseError::Truncated);
    }
    let icao24 = u32::from_be_bytes([0, data[1], data[2], data[3]]) & 0xFFFFFF;
    Ok(AdsbFrame {
        icao24,
        callsign: Some("DUMMY".to_string()),
        emergency: false,
    })
}
