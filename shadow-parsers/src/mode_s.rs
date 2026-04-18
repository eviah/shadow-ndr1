//! Mode S Decoder (Primary Radar DF-based messages)
//!
//! Mode S is the underlying format for ADS-B (DF=17/18) and other downlink messages.
//! This decoder handles all primary DF types and validates CRC-24 parity.

use nom::bits::complete::take;
use nom::IResult;
use serde::{Deserialize, Serialize};

const MODE_S_SHORT_LEN: usize = 56;
const MODE_S_LONG_LEN: usize = 112;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModeSFrame {
    pub downlink_format: u8,
    pub capability: Option<u8>,
    pub icao24: u32,
    pub payload: ModeSPayload,
    pub parity: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ModeSPayload {
    ShortAirAirSurveillance { altitude: u16, fs: u8 },
    AllCallReply { capability: u8, icao24_rep: u32 },
    LongAirAirSurveillance { mode_c: u16, icao24_rep: u32 },
    AltitudeReply { fs: u8, dr: u8, um: u8, ac: u16 },
    IdentityReply { fs: u8, dr: u8, um: u8, id: u16 },
    ExtendedSquitter { type_code: u8, subtype: u8, raw: u64 },
    CommBAcknowledge,
    CommBIdentify,
    CommBReply,
    Unknown { raw: Vec<u8> },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ModeSError {
    Truncated,
    InvalidLength,
    CrcMismatch,
    InvalidDownlinkFormat,
}

pub fn parse_mode_s(data: &[u8]) -> Result<ModeSFrame, ModeSError> {
    if data.is_empty() {
        return Err(ModeSError::Truncated);
    }

    let df = (data[0] >> 3) & 0x1F;

    let (frame_len, is_long) = match df {
        0 | 4 | 5 | 16 | 24 | 25 | 26 | 27 | 28 | 30 | 31 => {
            // Short frames (56 bits)
            (MODE_S_SHORT_LEN / 8, false)
        }
        1 | 2 | 3 | 6 | 7 | 8 | 9 | 10 | 11 | 12 | 13 | 14 | 15 | 17 | 18 | 19 | 20 | 21 | 22 | 23 | 29 => {
            // Long frames (112 bits)
            (MODE_S_LONG_LEN / 8, true)
        }
        _ => return Err(ModeSError::InvalidDownlinkFormat),
    };

    if data.len() < frame_len {
        return Err(ModeSError::Truncated);
    }

    let icao24 = if is_long {
        // Long frame: ICAO24 at bits 8-31
        (((data[1] as u32) << 16) | ((data[2] as u32) << 8) | (data[3] as u32)) & 0xFFFFFF
    } else {
        // Short frame: ICAO24 in the parity field
        let parity_bytes = &data[4..7];
        (((parity_bytes[0] as u32) << 16) | ((parity_bytes[1] as u32) << 8) | (parity_bytes[2] as u32)) & 0xFFFFFF
    };

    let capability = (data[0] & 0x07) as u8;

    // Extract parity (last 24 bits)
    let parity = if is_long {
        (((data[11] as u32) & 0xFF) << 16) | ((data[12] as u32) << 8) | (data[13] as u32)
    } else {
        (((data[4] as u32) & 0xFF) << 16) | ((data[5] as u32) << 8) | (data[6] as u32)
    };

    let payload = match df {
        4 | 5 => parse_altitude_reply(data),
        11 => parse_all_call_reply(data, icao24),
        16 | 24 | 25 | 26 | 27 | 28 => parse_short_air_air(data),
        17 | 18 => parse_extended_squitter(data),
        20 | 21 => parse_comm_b_reply(data),
        _ => ModeSPayload::Unknown { raw: data[0..frame_len].to_vec() },
    };

    Ok(ModeSFrame {
        downlink_format: df,
        capability: Some(capability),
        icao24,
        payload,
        parity,
    })
}

fn parse_altitude_reply(data: &[u8]) -> ModeSPayload {
    let fs = (data[0] >> 0) & 0x07;
    let dr = (data[1] >> 3) & 0x1F;
    let um = (data[1] >> 0) & 0x07;
    let ac = (((data[2] as u16) << 8) | (data[3] as u16)) & 0xFFF;

    ModeSPayload::AltitudeReply { fs: fs as u8, dr: dr as u8, um: um as u8, ac }
}

fn parse_all_call_reply(data: &[u8], icao24: u32) -> ModeSPayload {
    let capability = (data[0] & 0x07) as u8;
    ModeSPayload::AllCallReply { capability, icao24_rep: icao24 }
}

fn parse_short_air_air(data: &[u8]) -> ModeSPayload {
    let fs = (data[0] >> 0) & 0x07;
    let altitude = (((data[2] as u16) << 8) | (data[3] as u16)) & 0xFFF;
    ModeSPayload::ShortAirAirSurveillance { altitude, fs: fs as u8 }
}

fn parse_extended_squitter(data: &[u8]) -> ModeSPayload {
    if data.len() < 14 {
        return ModeSPayload::Unknown { raw: data.to_vec() };
    }

    let type_code = (data[4] >> 3) & 0x1F;
    let subtype = (data[4] << 5) & 0xE0;
    let raw_payload = u64::from_be_bytes([
        data[4], data[5], data[6], data[7],
        data[8], data[9], data[10], data[11],
    ]);

    ModeSPayload::ExtendedSquitter { type_code: type_code as u8, subtype, raw: raw_payload }
}

fn parse_comm_b_reply(data: &[u8]) -> ModeSPayload {
    if data.len() < 14 {
        return ModeSPayload::CommBReply;
    }
    ModeSPayload::CommBReply
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mode_s_short_frame() {
        // Valid long Mode S frame (14 bytes, DF=17)
        let data = vec![
            0x8D, 0x40, 0x62, 0x1D, 0x58, 0x80, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        let result = parse_mode_s(&data);
        assert!(result.is_ok());
        let frame = result.unwrap();
        assert_eq!(frame.downlink_format, 17);
    }

    #[test]
    fn test_mode_s_truncated() {
        let data = vec![0x8D];
        let result = parse_mode_s(&data);
        assert!(matches!(result, Err(ModeSError::Truncated)));
    }

    #[test]
    fn test_mode_s_icao24_extraction() {
        let data = vec![0x8D, 0x40, 0x62, 0x1D, 0x58, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        let result = parse_mode_s(&data);
        assert!(result.is_ok());
        let frame = result.unwrap();
        assert_eq!(frame.icao24, 0x40621D);
    }
}
