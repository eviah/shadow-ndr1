//! Common types and utilities for Shadow NDR aviation protocol parsers.

pub mod criticality;
pub mod threat;
pub mod timestamp;
pub mod parseable;
pub mod streaming;
pub mod pool;

// Re-export commonly used items
pub use criticality::AviationCriticality;
pub use threat::{Threat, ThreatType};
pub use timestamp::TimestampNanos;
pub use parseable::Parseable;
pub use streaming::StreamingParser;
pub use pool::{BufferPool, ParseError};
