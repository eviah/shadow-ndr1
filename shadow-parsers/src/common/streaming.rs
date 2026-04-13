//! Streaming parser for high‑throughput environments.

use crate::common::parseable::Parseable;
use crate::common::pool::ParseError;
use std::marker::PhantomData;

/// Generic streaming parser that feeds bytes and yields complete frames.
pub struct StreamingParser<P: Parseable> {
    buffer: Vec<u8>,
    max_buffer_size: usize,
    _phantom: PhantomData<P>,
}

impl<P: Parseable> StreamingParser<P> {
    /// Create a new streaming parser with default capacity.
    pub fn new() -> Self {
        Self::with_capacity(4096)
    }

    /// Create a new streaming parser with given initial buffer capacity.
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            buffer: Vec::with_capacity(capacity),
            max_buffer_size: capacity * 4,
            _phantom: PhantomData,
        }
    }

    /// Feed a chunk of data and return any complete frames.
    pub fn feed(&mut self, chunk: &[u8]) -> Result<Vec<P>, ParseError> {
        if self.buffer.len() + chunk.len() > self.max_buffer_size {
            return Err(ParseError::ParseError {
                offset: 0,
                reason: "buffer would exceed maximum size".to_string(),
            });
        }
        self.buffer.extend_from_slice(chunk);

        let mut results = Vec::new();
        let mut offset = 0;

        while offset < self.buffer.len() {
            match P::parse_with_consumed(&self.buffer[offset..]) {
                Ok((frame, consumed)) => {
                    results.push(frame);
                    offset += consumed;
                }
                Err(_) => {
                    // Not enough data, break and wait for more
                    break;
                }
            }
        }

        // Remove processed bytes
        if offset > 0 {
            self.buffer.drain(0..offset);
        }

        Ok(results)
    }

    /// Reset the internal buffer.
    pub fn reset(&mut self) {
        self.buffer.clear();
    }

    /// Returns the number of bytes currently buffered.
    pub fn buffered_len(&self) -> usize {
        self.buffer.len()
    }
}

impl<P: Parseable> Default for StreamingParser<P> {
    fn default() -> Self {
        Self::new()
    }
}
