//! VDL Mode 2 parser module
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VdlFrame {
    pub source: String,
    pub destination: String,
}

pub fn parse_vdl(data: &[u8]) -> Result<VdlFrame, crate::common::pool::ParseError> {
    Ok(VdlFrame {
        source: hex::encode(&data[0..6]),
        destination: hex::encode(&data[6..12]),
    })
}
