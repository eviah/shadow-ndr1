//! CPDLC Decoder (Controller Pilot Data Link Communications)
//!
//! CPDLC implements FANS-1/A messaging for automatic controller-to-pilot communications.
//! Uses ASN.1 encoding (ITU-T X.690) with variable-length message elements.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CpdlcFrame {
    pub aircraft_id: String,
    pub message_id: u16,
    pub message_type: CpdlcMessageType,
    pub elements: Vec<CpdlcElement>,
    pub response_required: bool,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum CpdlcMessageType {
    AirworthinessClearance,
    DepartureInformation,
    StartupApproval,
    PushbackApproval,
    TaxiClearance,
    TakeoffClearance,
    ClimbClearance,
    CruiseClearance,
    DescentClearance,
    ApproachClearance,
    LandingClearance,
    HoldingInstructions,
    GoAround,
    AirspeedInstruction,
    HeadingInstruction,
    AltitudeInstruction,
    LevelOffInstruction,
    EmergencyInstruction,
    RequestResponse,
    Report,
    SystemMessage,
    FlightPlanModification,
    Unknown(u8),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CpdlcElement {
    Altitude { feet: u16, incremental: bool },
    Heading { degrees: u16 },
    Speed { knots: u16 },
    VerticalRate { fpm: i16 },
    Route { waypoints: Vec<String> },
    Frequency { mhz: f32 },
    DirectTo { waypoint: String },
    Text(String),
    Unknown(Vec<u8>),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CpdlcError {
    Truncated,
    InvalidFormat,
    InvalidMessage,
    UnknownMessageType,
}

pub fn parse_cpdlc(data: &[u8]) -> Result<CpdlcFrame, CpdlcError> {
    if data.len() < 10 {
        return Err(CpdlcError::Truncated);
    }

    // Byte 0: Aircraft ID length (variable, typically 7 chars)
    let aircraft_id_len = (data[0] as usize) & 0x7F;
    if aircraft_id_len == 0 || aircraft_id_len > 8 || 1 + aircraft_id_len > data.len() {
        return Err(CpdlcError::Truncated);
    }

    let aircraft_id = String::from_utf8_lossy(&data[1..1 + aircraft_id_len]).to_string();

    let mut offset = 1 + aircraft_id_len;

    // Message ID (2 bytes, big-endian)
    if offset + 2 > data.len() {
        return Err(CpdlcError::Truncated);
    }
    let message_id = u16::from_be_bytes([data[offset], data[offset + 1]]);
    offset += 2;

    // Message Type (1 byte)
    if offset >= data.len() {
        return Err(CpdlcError::Truncated);
    }
    let msg_type_byte = data[offset];
    let message_type = parse_message_type(msg_type_byte);
    offset += 1;

    // Response Required flag
    let response_required = (data[offset] & 0x80) != 0;
    offset += 1;

    // Parse elements until end of data
    let mut elements = Vec::new();
    while offset < data.len() {
        match parse_element(&data[offset..]) {
            Ok((element, consumed)) => {
                elements.push(element);
                offset += consumed;
            }
            Err(_) => break,
        }
    }

    Ok(CpdlcFrame {
        aircraft_id,
        message_id,
        message_type,
        elements,
        response_required,
    })
}

fn parse_message_type(byte: u8) -> CpdlcMessageType {
    match byte {
        0x01 => CpdlcMessageType::AirworthinessClearance,
        0x02 => CpdlcMessageType::DepartureInformation,
        0x03 => CpdlcMessageType::StartupApproval,
        0x04 => CpdlcMessageType::PushbackApproval,
        0x05 => CpdlcMessageType::TaxiClearance,
        0x06 => CpdlcMessageType::TakeoffClearance,
        0x07 => CpdlcMessageType::ClimbClearance,
        0x08 => CpdlcMessageType::CruiseClearance,
        0x09 => CpdlcMessageType::DescentClearance,
        0x0A => CpdlcMessageType::ApproachClearance,
        0x0B => CpdlcMessageType::LandingClearance,
        0x0C => CpdlcMessageType::HoldingInstructions,
        0x0D => CpdlcMessageType::GoAround,
        0x0E => CpdlcMessageType::AirspeedInstruction,
        0x0F => CpdlcMessageType::HeadingInstruction,
        0x10 => CpdlcMessageType::AltitudeInstruction,
        0x11 => CpdlcMessageType::LevelOffInstruction,
        0x12 => CpdlcMessageType::EmergencyInstruction,
        0x13 => CpdlcMessageType::RequestResponse,
        0x14 => CpdlcMessageType::Report,
        0x15 => CpdlcMessageType::SystemMessage,
        0x16 => CpdlcMessageType::FlightPlanModification,
        _ => CpdlcMessageType::Unknown(byte),
    }
}

fn parse_element(data: &[u8]) -> Result<(CpdlcElement, usize), CpdlcError> {
    if data.is_empty() {
        return Err(CpdlcError::Truncated);
    }

    let element_type = data[0];

    match element_type {
        0x20..=0x30 => {
            // Altitude element
            if data.len() < 3 {
                return Err(CpdlcError::Truncated);
            }
            let feet = u16::from_be_bytes([data[1], data[2]]);
            let incremental = (element_type & 0x01) != 0;
            Ok((
                CpdlcElement::Altitude { feet, incremental },
                3,
            ))
        }
        0x40..=0x41 => {
            // Heading element
            if data.len() < 3 {
                return Err(CpdlcError::Truncated);
            }
            let degrees = u16::from_be_bytes([data[1], data[2]]);
            Ok((CpdlcElement::Heading { degrees }, 3))
        }
        0x50..=0x51 => {
            // Speed element
            if data.len() < 3 {
                return Err(CpdlcError::Truncated);
            }
            let knots = u16::from_be_bytes([data[1], data[2]]);
            Ok((CpdlcElement::Speed { knots }, 3))
        }
        0x60..=0x61 => {
            // Vertical rate element
            if data.len() < 3 {
                return Err(CpdlcError::Truncated);
            }
            let fpm = i16::from_be_bytes([data[1], data[2]]);
            Ok((CpdlcElement::VerticalRate { fpm }, 3))
        }
        0x70..=0x7F => {
            // Text element (variable length)
            if data.len() < 2 {
                return Err(CpdlcError::Truncated);
            }
            let len = data[1] as usize;
            if data.len() < 2 + len {
                return Err(CpdlcError::Truncated);
            }
            let text = String::from_utf8_lossy(&data[2..2 + len]).to_string();
            Ok((CpdlcElement::Text(text), 2 + len))
        }
        _ => {
            // Unknown element - consume 1 byte and continue
            Ok((CpdlcElement::Unknown(vec![element_type]), 1))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cpdlc_basic_message() {
        let mut data = vec![0x07]; // Aircraft ID length
        data.extend_from_slice(b"N123ABC");
        data.extend_from_slice(&[0x00, 0x01]); // Message ID
        data.push(0x08); // Message Type: CruiseClearance
        data.push(0x00); // Flags
        let result = parse_cpdlc(&data);
        assert!(result.is_ok());
        let frame = result.unwrap();
        assert_eq!(frame.aircraft_id, "N123ABC");
        assert_eq!(frame.message_id, 1);
    }

    #[test]
    fn test_cpdlc_truncated() {
        let data = vec![0x07, 0x00];
        let result = parse_cpdlc(&data);
        assert!(matches!(result, Err(CpdlcError::Truncated)));
    }

    #[test]
    fn test_altitude_element() {
        let data = vec![0x20, 0x27, 0x10]; // Altitude 10000 feet
        let result = parse_element(&data);
        assert!(result.is_ok());
        let (element, _) = result.unwrap();
        match element {
            CpdlcElement::Altitude { feet, .. } => assert_eq!(feet, 10000),
            _ => panic!("Wrong element type"),
        }
    }
}
