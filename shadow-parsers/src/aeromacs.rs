//! AeroMACS Decoder (IEEE 802.16e WiMAX Airport Communications)
//!
//! AeroMACS provides broadband wireless communications at airports using WiMAX.
//! Operates at 5.0-5.25 GHz for aircraft and ground vehicle movement areas.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AeroMacsFrame {
    pub frame_type: AeroMacsFrameType,
    pub connection_id: u16,
    pub sequence_number: u8,
    pub length: u16,
    pub payload: AeroMacsPayload,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum AeroMacsFrameType {
    ManagementBroadcast,
    DownlinkMapDIUC,
    UplinkMapUiuc,
    RNG_RSP,
    SBC_REQ,
    SBC_RSP,
    REG_REQ,
    REG_RSP,
    PKM_REQ,
    PKM_RSP,
    DataGrant,
    DataTransport,
    Unknown(u8),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AeroMacsPayload {
    UCD(UplinkChannelDescriptor),
    DCD(DownlinkChannelDescriptor),
    DL_MAP(DownlinkMap),
    UL_MAP(UplinkMap),
    RangeResponse { status: u8 },
    Registration { primary_management_cid: u16 },
    PKMRequest { auth_key_version: u8 },
    DataGrant { cid: u16, interval: u8 },
    Raw(Vec<u8>),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UplinkChannelDescriptor {
    pub config_change_count: u8,
    pub ranging_backoff_start: u8,
    pub ranging_backoff_end: u8,
    pub request_backoff_start: u8,
    pub request_backoff_end: u8,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DownlinkChannelDescriptor {
    pub config_change_count: u8,
    pub downlink_channel_id: u8,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DownlinkMap {
    pub map_type: u8,
    pub dcd_count: u8,
    pub num_ie: u16,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UplinkMap {
    pub map_type: u8,
    pub ucd_count: u8,
    pub num_ie: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AeroMacsError {
    Truncated,
    InvalidFormat,
    UnknownFrameType,
}

pub fn parse_aeromacs(data: &[u8]) -> Result<AeroMacsFrame, AeroMacsError> {
    if data.len() < 12 {
        return Err(AeroMacsError::Truncated);
    }

    // Byte 0: Frame Control Header (FCH)
    let frame_control = data[0];
    let frame_type_bits = (frame_control >> 3) & 0x0F;
    let ec = (frame_control & 0x07);

    // Byte 1-2: Connection ID (CID)
    let connection_id = u16::from_be_bytes([data[1], data[2]]);

    // Byte 3: Sequence Number
    let sequence_number = data[3];

    // Byte 4-5: Length (PDU length in bytes)
    let length = u16::from_be_bytes([data[4], data[5]]);

    let frame_type = match frame_type_bits {
        0 => AeroMacsFrameType::ManagementBroadcast,
        1 => AeroMacsFrameType::DownlinkMapDIUC,
        2 => AeroMacsFrameType::UplinkMapUiuc,
        3 => AeroMacsFrameType::RNG_RSP,
        4 => AeroMacsFrameType::SBC_REQ,
        5 => AeroMacsFrameType::SBC_RSP,
        6 => AeroMacsFrameType::REG_REQ,
        7 => AeroMacsFrameType::REG_RSP,
        8 => AeroMacsFrameType::PKM_REQ,
        9 => AeroMacsFrameType::PKM_RSP,
        10 => AeroMacsFrameType::DataGrant,
        11 => AeroMacsFrameType::DataTransport,
        _ => AeroMacsFrameType::Unknown(frame_type_bits),
    };

    // Extract payload
    let payload_start = 6;
    let payload_end = (payload_start + length as usize).min(data.len());
    let payload_bytes = if payload_end > payload_start {
        &data[payload_start..payload_end]
    } else {
        &[]
    };

    let payload = parse_payload(frame_type, payload_bytes);

    Ok(AeroMacsFrame {
        frame_type,
        connection_id,
        sequence_number,
        length,
        payload,
    })
}

fn parse_payload(frame_type: AeroMacsFrameType, data: &[u8]) -> AeroMacsPayload {
    match frame_type {
        AeroMacsFrameType::ManagementBroadcast => {
            if data.is_empty() {
                return AeroMacsPayload::Raw(vec![]);
            }

            let management_type = data[0];
            match management_type {
                0x01 => {
                    // UCD
                    if data.len() < 6 {
                        return AeroMacsPayload::Raw(data.to_vec());
                    }
                    AeroMacsPayload::UCD(UplinkChannelDescriptor {
                        config_change_count: data[1],
                        ranging_backoff_start: data[2],
                        ranging_backoff_end: data[3],
                        request_backoff_start: data[4],
                        request_backoff_end: data[5],
                    })
                }
                0x02 => {
                    // DCD
                    if data.len() < 3 {
                        return AeroMacsPayload::Raw(data.to_vec());
                    }
                    AeroMacsPayload::DCD(DownlinkChannelDescriptor {
                        config_change_count: data[1],
                        downlink_channel_id: data[2],
                    })
                }
                _ => AeroMacsPayload::Raw(data.to_vec()),
            }
        }
        AeroMacsFrameType::DownlinkMapDIUC => {
            if data.len() < 4 {
                return AeroMacsPayload::Raw(data.to_vec());
            }
            let num_ie = u16::from_be_bytes([data[2], data[3]]);
            AeroMacsPayload::DL_MAP(DownlinkMap {
                map_type: data[0],
                dcd_count: data[1],
                num_ie,
            })
        }
        AeroMacsFrameType::UplinkMapUiuc => {
            if data.len() < 4 {
                return AeroMacsPayload::Raw(data.to_vec());
            }
            let num_ie = u16::from_be_bytes([data[2], data[3]]);
            AeroMacsPayload::UL_MAP(UplinkMap {
                map_type: data[0],
                ucd_count: data[1],
                num_ie,
            })
        }
        AeroMacsFrameType::RNG_RSP => {
            if data.is_empty() {
                return AeroMacsPayload::RangeResponse { status: 0 };
            }
            AeroMacsPayload::RangeResponse { status: data[0] }
        }
        AeroMacsFrameType::REG_RSP => {
            if data.len() < 2 {
                return AeroMacsPayload::Raw(data.to_vec());
            }
            let cid = u16::from_be_bytes([data[0], data[1]]);
            AeroMacsPayload::Registration { primary_management_cid: cid }
        }
        AeroMacsFrameType::PKM_REQ => {
            if data.is_empty() {
                return AeroMacsPayload::PKMRequest { auth_key_version: 0 };
            }
            AeroMacsPayload::PKMRequest { auth_key_version: data[0] }
        }
        AeroMacsFrameType::DataGrant => {
            if data.len() < 3 {
                return AeroMacsPayload::Raw(data.to_vec());
            }
            let cid = u16::from_be_bytes([data[0], data[1]]);
            AeroMacsPayload::DataGrant {
                cid,
                interval: data[2],
            }
        }
        _ => AeroMacsPayload::Raw(data.to_vec()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_aeromacs_basic_frame() {
        let data = vec![
            0x00, // Frame control (management broadcast)
            0x00, 0x01, // Connection ID = 1
            0x00, // Sequence number
            0x00, 0x10, // Length = 16 bytes
            // Payload...
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        let result = parse_aeromacs(&data);
        assert!(result.is_ok());
        let frame = result.unwrap();
        assert_eq!(frame.connection_id, 1);
    }

    #[test]
    fn test_aeromacs_truncated() {
        let data = vec![0x00, 0x00];
        let result = parse_aeromacs(&data);
        assert!(matches!(result, Err(AeroMacsError::Truncated)));
    }

    #[test]
    fn test_aeromacs_frame_types() {
        let mut data = vec![0x00; 12];
        data[0] = 0x08; // PKM_REQ frame type
        let result = parse_aeromacs(&data);
        assert!(result.is_ok());
        let frame = result.unwrap();
        assert!(matches!(frame.frame_type, AeroMacsFrameType::PKM_REQ));
    }
}
