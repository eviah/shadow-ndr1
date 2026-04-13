//! Buffer pool for zero‑allocation parsing.

use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use thiserror::Error;

/// Errors that can occur during parsing.
#[derive(Error, Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum ParseError {
    #[error("Invalid data: {reason}")]
    InvalidData { reason: String },
    #[error("Packet truncated")]
    Truncated,
    #[error("Parse error at offset {offset}: {reason}")]
    ParseError { offset: usize, reason: String },
}

/// A pool of reusable buffers to reduce allocations.
#[derive(Clone)]
pub struct BufferPool {
    buffers: Arc<RwLock<Vec<Vec<u8>>>>,
    capacity: usize,
}

impl BufferPool {
    /// Create a new pool with the given number of buffers and capacity.
    pub fn new(pool_size: usize, buffer_capacity: usize) -> Self {
        let mut buffers = Vec::with_capacity(pool_size);
        for _ in 0..pool_size {
            buffers.push(Vec::with_capacity(buffer_capacity));
        }
        Self {
            buffers: Arc::new(RwLock::new(buffers)),
            capacity: buffer_capacity,
        }
    }

    /// Acquire a buffer from the pool, or None if none available.
    pub fn acquire(&self) -> Option<Vec<u8>> {
        let mut bufs = self.buffers.write();
        bufs.pop()
    }

    /// Return a buffer to the pool for reuse.
    pub fn release(&self, mut buf: Vec<u8>) {
        if buf.capacity() >= self.capacity {
            buf.clear();
            let mut bufs = self.buffers.write();
            if bufs.len() < 16 {
                bufs.push(buf);
            }
        }
    }

    /// Statistics: (available buffers, capacity).
    pub fn stats(&self) -> (usize, usize) {
        let bufs = self.buffers.read();
        (bufs.len(), self.capacity)
    }

    /// Pre‑allocate a buffer from the pool, or create a new one.
    pub fn take(&self) -> Vec<u8> {
        self.acquire().unwrap_or_else(|| Vec::with_capacity(self.capacity))
    }
}
