//! Nanosecond‑precision timestamps with chrono integration.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// A timestamp with nanosecond precision since Unix epoch.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct TimestampNanos(pub u64);

impl TimestampNanos {
    /// Returns the current system time as a TimestampNanos.
    pub fn now() -> Self {
        Self(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos() as u64,
        )
    }

    /// Converts to a DateTime<Utc> for human‑readable formatting.
    pub fn to_datetime(&self) -> DateTime<Utc> {
        DateTime::from_timestamp_nanos(self.0 as i64)
    }

    /// Returns the duration since this timestamp (absolute).
    pub fn elapsed(&self) -> Duration {
        let now = Self::now();
        Duration::from_nanos(now.0.saturating_sub(self.0))
    }

    /// Returns 	rue if this timestamp is before the given one.
    pub fn is_before(&self, other: &Self) -> bool {
        self.0 < other.0
    }

    /// Returns 	rue if this timestamp is after the given one.
    pub fn is_after(&self, other: &Self) -> bool {
        self.0 > other.0
    }

    /// Creates a TimestampNanos from a SystemTime.
    pub fn from_system_time(time: SystemTime) -> Self {
        Self(
            time.duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos() as u64,
        )
    }

    /// Converts to a SystemTime.
    pub fn to_system_time(&self) -> SystemTime {
        UNIX_EPOCH + Duration::from_nanos(self.0)
    }
}

impl Default for TimestampNanos {
    fn default() -> Self {
        Self::now()
    }
}

impl From<SystemTime> for TimestampNanos {
    fn from(time: SystemTime) -> Self {
        Self::from_system_time(time)
    }
}
