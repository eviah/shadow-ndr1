//! ACARS parser module
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AcarsFrame {
    pub aircraft_id: String,
    pub message_text: String,
}

pub fn parse_acars(data: &[u8]) -> Result<AcarsFrame, crate::common::pool::ParseError> {
    let s = String::from_utf8_lossy(data);
    Ok(AcarsFrame {
        aircraft_id: "UNKNOWN".to_string(),
        message_text: s.to_string(),
    })
}
