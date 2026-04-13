//! AeroMACS parser module
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AeroMacsFrame {
    pub source_mac: [u8; 6],
    pub dest_mac: [u8; 6],
}

pub fn parse_aeromacs(data: &[u8]) -> Result<AeroMacsFrame, crate::common::pool::ParseError> {
    if data.len() < 14 {
        return Err(crate::common::pool::ParseError::Truncated);
    }
    let mut source = [0u8; 6];
    let mut dest = [0u8; 6];
    source.copy_from_slice(&data[0..6]);
    dest.copy_from_slice(&data[6..12]);
    Ok(AeroMacsFrame { source_mac: source, dest_mac: dest })
}
