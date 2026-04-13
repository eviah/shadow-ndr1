//! CPDLC parser module
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CpdlcFrame {
    pub aircraft_id: String,
    pub message: String,
}

pub fn parse_cpdlc(data: &[u8]) -> Result<CpdlcFrame, crate::common::pool::ParseError> {
    let s = String::from_utf8_lossy(data);
    Ok(CpdlcFrame {
        aircraft_id: "UNKNOWN".to_string(),
        message: s.to_string(),
    })
}
