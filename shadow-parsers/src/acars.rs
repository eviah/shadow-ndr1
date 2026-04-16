//! ACARS (Aircraft Communications Addressing and Reporting System) Parser
//! 
//! Project Titan Aerospace Decoder
//! Deep ARINC 618 protocol decoding over IP. Extracts technical ACKs,
//! tail prefixes, labels, and text payloads with fault tolerance.

use nom::bytes::complete::{take_until, take_while_m_n};
use nom::character::complete::anychar;
use nom::combinator::{map_res, opt};
use nom::sequence::tuple;
use nom::IResult;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AcarsFrame {
    pub mode: char,
    pub aircraft_id: String,
    pub ack: char,
    pub label: String,
    pub block_id: char,
    pub message_seq: Option<String>,
    pub flight_id: Option<String>,
    pub message_text: String,
}

#[derive(Debug, thiserror::Error)]
pub enum AcarsError {
    #[error("Not an ACARS message")]
    InvalidFormat,
    #[error("Missing Start of Header (SOH)")]
    MissingSoh,
    #[error("Parse failed: {0}")]
    ParseFailed(String),
}

/// SOH = 0x01
const SOH: u8 = 0x01;
/// STX = 0x02
const STX: u8 = 0x02;
/// ETX = 0x03
const ETX: u8 = 0x03;

pub fn parse_acars(data: &[u8]) -> Result<AcarsFrame, AcarsError> {
    if data.is_empty() || data[0] != SOH {
        return Err(AcarsError::MissingSoh);
    }

    match parse_acars_nom(&data[1..]) {
        Ok((_, frame)) => Ok(frame),
        Err(nom::Err::Error(e)) | Err(nom::Err::Failure(e)) => {
            Err(AcarsError::ParseFailed(format!("{:?}", e)))
        }
        Err(nom::Err::Incomplete(_)) => Err(AcarsError::InvalidFormat),
    }
}

fn is_alphanumeric_or_symbol(c: u8) -> bool {
    c.is_ascii_graphic() || c.is_ascii_whitespace()
}

fn parse_acars_nom(input: &[u8]) -> IResult<&[u8], AcarsFrame> {
    // Mode (1 char)
    let (input, mode_char) = anychar(input)?;
    // Aircraft reg (7 chars)
    let (input, reg_bytes) = nom::bytes::complete::take(7usize)(input)?;
    let aircraft_id = String::from_utf8_lossy(reg_bytes).trim().to_string();

    // Technical ACK (1 char)
    let (input, ack) = anychar(input)?;
    // Label (2 chars)
    let (input, label_bytes) = nom::bytes::complete::take(2usize)(input)?;
    let label = String::from_utf8_lossy(label_bytes).to_string();

    // Block ID (1 char)
    let (input, block_id) = anychar(input)?;

    // STX (Start of Text) indicates that payload is beginning
    // Message sequence / flight num might be next if STX isn't immediately found.
    // For a rigorous ARINC 618, we would scan until STX.
    let (input, pre_text) = take_until(&[STX][..])(input)?;
    let (mut input, _) = nom::bytes::complete::take(1usize)(input)?; // consume STX
    
    let mut message_seq = None;
    let mut flight_id = None;

    if pre_text.len() >= 4 {
        message_seq = Some(String::from_utf8_lossy(&pre_text[0..4]).to_string());
    }
    if pre_text.len() >= 10 {
        flight_id = Some(String::from_utf8_lossy(&pre_text[4..10]).to_string());
    }

    // Now capture everything until ETX
    let (input, text_bytes) = take_until(&[ETX][..])(input)?;
    let message_text = String::from_utf8_lossy(text_bytes).trim().to_string();

    Ok((
        input, // Remaining (usually checksum)
        AcarsFrame {
            mode: mode_char,
            aircraft_id,
            ack,
            label,
            block_id,
            message_seq,
            flight_id,
            message_text,
        }
    ))
}
