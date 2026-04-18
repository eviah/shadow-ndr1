//! VDL Mode 2 Decoder (Aviation VHF Data Link)
//!
//! VDL Mode 2 operates on aviation VHF frequencies for air-to-ground communication.
//! Uses AVLC (Aviation VHF Link Control) framing with ACARS payload support.

use serde::{Deserialize, Serialize};

const AVLC_FRAME_FLAG: u8 = 0x7E;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VdlFrame {
    pub frame_type: VdlFrameType,
    pub source_address: [u8; 3],
    pub dest_address: [u8; 3],
    pub sequence: u8,
    pub payload: VdlPayload,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum VdlFrameType {
    Information,
    Supervisory,
    Unnumbered,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum VdlPayload {
    Acars(AcarsFrame),
    AircraftCommunicationAddressing(String),
    VdlManagement,
    RawData(Vec<u8>),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AcarsFrame {
    pub aircraft_id: String,
    pub mode: char,
    pub label: String,
    pub block_id: char,
    pub message_id: String,
    pub end_of_msg: char,
    pub text: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VdlError {
    Truncated,
    InvalidFrame,
    BadChecksum,
    InvalidPayload,
}

pub fn parse_vdl(data: &[u8]) -> Result<VdlFrame, VdlError> {
    if data.len() < 15 {
        return Err(VdlError::Truncated);
    }

    // Skip AVLC flags (0x7E) if present
    let mut offset = 0;
    if data[0] == AVLC_FRAME_FLAG {
        offset = 1;
    }

    if offset + 14 > data.len() {
        return Err(VdlError::Truncated);
    }

    // Byte 0: Address (octet 1)
    let address_octet1 = data[offset];
    let dest_address = [
        data[offset],
        data[offset + 1],
        data[offset + 2],
    ];

    // Byte 3: Control field determines frame type
    let control = data[offset + 3];
    let frame_type = if (control & 0x01) == 0 {
        VdlFrameType::Information
    } else if (control & 0x03) == 0x01 {
        VdlFrameType::Supervisory
    } else {
        VdlFrameType::Unnumbered
    };

    // Extract source address (bytes 4-6)
    let source_address = [
        data[offset + 4],
        data[offset + 5],
        data[offset + 6],
    ];

    let sequence = (control >> 1) & 0x07;

    // Payload starts at byte 7, ends 3 bytes before end (for FCS)
    let payload_start = offset + 7;
    let payload_end = if data.len() > offset + 10 {
        data.len() - 3
    } else {
        data.len()
    };

    let payload_bytes = if payload_end > payload_start {
        &data[payload_start..payload_end]
    } else {
        &[]
    };

    // Try to parse as ACARS
    let payload = match parse_acars_payload(payload_bytes) {
        Ok(acars) => VdlPayload::Acars(acars),
        Err(_) => VdlPayload::RawData(payload_bytes.to_vec()),
    };

    Ok(VdlFrame {
        frame_type,
        source_address,
        dest_address,
        sequence,
        payload,
    })
}

fn parse_acars_payload(data: &[u8]) -> Result<AcarsFrame, VdlError> {
    if data.len() < 15 {
        return Err(VdlError::Truncated);
    }

    // ACARS format: Aircraft ID (7) + Mode (1) + Label (2) + Block (1) + Msg ID (3) + EOM (1) + Text
    let aircraft_id = String::from_utf8_lossy(&data[0..7]).trim_end().to_string();
    let mode = data[7] as char;
    let label = String::from_utf8_lossy(&data[8..10]).to_string();
    let block_id = data[10] as char;
    let message_id = String::from_utf8_lossy(&data[11..14]).trim_end().to_string();
    let end_of_msg = data[14] as char;

    let text = if data.len() > 15 {
        String::from_utf8_lossy(&data[15..]).trim_end().to_string()
    } else {
        String::new()
    };

    Ok(AcarsFrame {
        aircraft_id,
        mode,
        label,
        block_id,
        message_id,
        end_of_msg,
        text,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vdl_basic_frame() {
        let mut data = vec![0x7E, 0x21, 0x03, 0x00, 0x10, 0x20, 0x30, 0x40];
        data.extend_from_slice(&[0x00; 20]); // Sufficient for parse_vdl min length
        let result = parse_vdl(&data);
        assert!(result.is_ok());
    }

    #[test]
    fn test_vdl_truncated() {
        let data = vec![0x7E, 0x21, 0x03];
        let result = parse_vdl(&data);
        assert!(matches!(result, Err(VdlError::Truncated)));
    }

    #[test]
    fn test_acars_parsing() {
        let acars_bytes = b"N123ABAQX0001#HELLO WORLD";
        let result = parse_acars_payload(&acars_bytes[..]);
        assert!(result.is_ok());
        let frame = result.unwrap();
        assert_eq!(frame.aircraft_id, "N123ABA");
        assert_eq!(frame.mode, 'Q');
    }
}
