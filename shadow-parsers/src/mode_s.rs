//! Mode S parser module
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModeSFrame {
    pub icao24: u32,
}

pub fn parse_mode_s(data: &[u8]) -> Result<ModeSFrame, crate::common::pool::ParseError> {
    if data.len() < 14 {
        return Err(crate::common::pool::ParseError::Truncated);
    }
    let icao24 = u32::from_be_bytes([0, data[1], data[2], data[3]]) & 0xFFFFFF;
    Ok(ModeSFrame { icao24 })
}
