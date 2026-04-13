//! Aviation-specific criticality levels used for threat prioritisation.

use serde::{Deserialize, Serialize};
use std::fmt;

/// Criticality of a detected aviation event.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum AviationCriticality {
    /// Normal operational data – no immediate action needed.
    Normal = 0,
    /// Warning – degraded accuracy, minor anomalies, but still safe.
    Warning = 1,
    /// Emergency – immediate attention required (e.g., 7700 squawk, hijack).
    Emergency = 2,
    /// System failure – data corrupted, unreliable, or system malfunction.
    SystemFailure = 3,
}

impl fmt::Display for AviationCriticality {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Normal => write!(f, "NORMAL"),
            Self::Warning => write!(f, "⚠️ WARNING"),
            Self::Emergency => write!(f, "🚨 EMERGENCY"),
            Self::SystemFailure => write!(f, "💀 SYSTEM_FAILURE"),
        }
    }
}

impl Default for AviationCriticality {
    fn default() -> Self {
        Self::Normal
    }
}
