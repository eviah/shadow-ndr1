//! Core parsing traits for all protocols.

use crate::common::pool::ParseError;

/// Trait for types that can be parsed from a byte slice with known consumed length.
pub trait Parseable: Sized {
    /// Parse a frame from bytes, returning the frame and number of bytes consumed.
    ///
    /// # Returns
    /// - Ok((frame, consumed)) on success.
    /// - Err(ParseError) if parsing fails.
    fn parse_with_consumed(data: &[u8]) -> Result<(Self, usize), ParseError>;

    /// Parse a frame assuming the entire slice is consumed.
    /// Default implementation calls parse_with_consumed and checks leftover bytes.
    fn parse(data: &[u8]) -> Result<Self, ParseError> {
        let (frame, consumed) = Self::parse_with_consumed(data)?;
        if consumed != data.len() {
            return Err(ParseError::ParseError {
                offset: consumed,
                reason: format!("Extra data after frame: {} bytes remaining", data.len() - consumed),
            });
        }
        Ok(frame)
    }
}
