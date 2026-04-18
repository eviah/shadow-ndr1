//! Threat Pattern Correlation System
//!
//! Detects coordinated attack patterns and fleet-level behavior anomalies.
//! Correlates individual threat signals into broader security incidents.

use std::collections::HashMap;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatEvent {
    pub icao24: u32,
    pub event_type: ThreatEventType,
    pub timestamp_ms: u64,
    pub severity: f32, // 0.0 = low, 1.0 = critical
    pub metadata: HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ThreatEventType {
    Spoofing,
    Teleportation,
    UnauthorizedEntry,
    CommunicationAnomaly,
    IdentityMismatch,
    PhysicsViolation,
    Unknown(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CorrelationCluster {
    pub cluster_id: u32,
    pub aircraft: Vec<u32>,
    pub event_count: u32,
    pub time_span_ms: u64,
    pub avg_severity: f32,
    pub pattern: String, // Description of detected pattern
    pub confidence: f32,
}

pub struct ThreatCorrelator {
    events: Vec<ThreatEvent>,
    clusters: Vec<CorrelationCluster>,
    next_cluster_id: u32,
    config: CorrelatorConfig,
}

#[derive(Debug, Clone)]
pub struct CorrelatorConfig {
    /// Time window for clustering threats (ms)
    pub correlation_window_ms: u64,
    /// Minimum aircraft for cluster formation
    pub min_cluster_size: u32,
    /// Severity threshold (0.0 - 1.0)
    pub severity_threshold: f32,
}

impl Default for CorrelatorConfig {
    fn default() -> Self {
        CorrelatorConfig {
            correlation_window_ms: 60000, // 1 minute
            min_cluster_size: 2,
            severity_threshold: 0.5,
        }
    }
}

impl ThreatCorrelator {
    /// Create new correlator
    pub fn new() -> Self {
        ThreatCorrelator {
            events: Vec::new(),
            clusters: Vec::new(),
            next_cluster_id: 1,
            config: CorrelatorConfig::default(),
        }
    }

    /// Create with custom config
    pub fn with_config(config: CorrelatorConfig) -> Self {
        ThreatCorrelator {
            events: Vec::new(),
            clusters: Vec::new(),
            next_cluster_id: 1,
            config,
        }
    }

    /// Record a threat event
    pub fn record_event(&mut self, event: ThreatEvent) {
        self.events.push(event);
    }

    /// Correlate events into clusters
    pub fn correlate(&mut self) -> Vec<CorrelationCluster> {
        self.clusters.clear();

        if self.events.is_empty() {
            return Vec::new();
        }

        // Sort events by timestamp
        self.events.sort_by_key(|e| e.timestamp_ms);

        let mut processed = vec![false; self.events.len()];

        for i in 0..self.events.len() {
            if processed[i] {
                continue;
            }

            let seed_event = &self.events[i];
            let mut cluster_aircraft = vec![seed_event.icao24];
            let mut cluster_events = vec![i];
            let mut total_severity = seed_event.severity;
            let earliest = seed_event.timestamp_ms;

            // Find correlated events within time window
            for j in (i + 1)..self.events.len() {
                if processed[j] {
                    continue;
                }

                let other_event = &self.events[j];

                // Check if within time window
                if other_event.timestamp_ms - earliest > self.config.correlation_window_ms {
                    break;
                }

                // Check if same threat type (correlation indicator)
                if self.are_events_related(seed_event, other_event) {
                    processed[j] = true;
                    cluster_aircraft.push(other_event.icao24);
                    cluster_events.push(j);
                    total_severity += other_event.severity;
                }
            }

            processed[i] = true;

            // Only create cluster if meaningful
            if cluster_aircraft.len() >= self.config.min_cluster_size as usize
                && total_severity / cluster_aircraft.len() as f32 >= self.config.severity_threshold
            {
                cluster_aircraft.sort();
                cluster_aircraft.dedup();

                let pattern = self.detect_pattern(&cluster_events);

                let cluster = CorrelationCluster {
                    cluster_id: self.next_cluster_id,
                    aircraft: cluster_aircraft,
                    event_count: cluster_events.len() as u32,
                    time_span_ms: self.events[*cluster_events.last().unwrap()].timestamp_ms - earliest,
                    avg_severity: total_severity / cluster_events.len() as f32,
                    pattern,
                    confidence: self.calculate_confidence(&cluster_events),
                };

                self.clusters.push(cluster);
                self.next_cluster_id += 1;
            }
        }

        self.clusters.clone()
    }

    /// Check if two events are related (same pattern)
    fn are_events_related(&self, e1: &ThreatEvent, e2: &ThreatEvent) -> bool {
        // Same threat type = strong correlation
        if e1.event_type == e2.event_type {
            return true;
        }

        // Spoofing + Identity mismatch = related
        match (&e1.event_type, &e2.event_type) {
            (ThreatEventType::Spoofing, ThreatEventType::IdentityMismatch) => true,
            (ThreatEventType::Teleportation, ThreatEventType::CommunicationAnomaly) => true,
            _ => false,
        }
    }

    /// Detect pattern from clustered events
    fn detect_pattern(&self, event_indices: &[usize]) -> String {
        if event_indices.is_empty() {
            return "UNKNOWN".to_string();
        }

        // Count event types
        let mut type_counts: HashMap<String, u32> = HashMap::new();
        for &idx in event_indices {
            let type_name = match &self.events[idx].event_type {
                ThreatEventType::Spoofing => "SPOOFING",
                ThreatEventType::Teleportation => "TELEPORTATION",
                ThreatEventType::UnauthorizedEntry => "UNAUTHORIZED_ENTRY",
                ThreatEventType::CommunicationAnomaly => "COMMS_ANOMALY",
                ThreatEventType::IdentityMismatch => "IDENTITY_MISMATCH",
                ThreatEventType::PhysicsViolation => "PHYSICS_VIOLATION",
                ThreatEventType::Unknown(s) => s.as_str(),
            };
            *type_counts.entry(type_name.to_string()).or_insert(0) += 1;
        }

        // Generate pattern description
        if type_counts.values().max() == Some(&(event_indices.len() as u32)) {
            // All same type
            format!(
                "COORDINATED_{}",
                type_counts.keys().next().unwrap_or(&"ATTACK".to_string())
            )
        } else if type_counts.len() > 1 {
            "MULTI_THREAT_CAMPAIGN".to_string()
        } else {
            "FLEET_ANOMALY".to_string()
        }
    }

    /// Calculate confidence in cluster (0.0 - 1.0)
    fn calculate_confidence(&self, event_indices: &[usize]) -> f32 {
        if event_indices.is_empty() {
            return 0.0;
        }

        let avg_severity = self.events[event_indices[0]].severity;
        let count_factor = (event_indices.len() as f32) / 10.0;

        (avg_severity * count_factor).min(1.0)
    }

    /// Get all clusters
    pub fn get_clusters(&self) -> &[CorrelationCluster] {
        &self.clusters
    }

    /// Get recent events
    pub fn get_events(&self, limit: usize) -> &[ThreatEvent] {
        if self.events.len() > limit {
            &self.events[self.events.len() - limit..]
        } else {
            &self.events
        }
    }

    /// Clear old events
    pub fn cleanup(&mut self, before_ms: u64) {
        self.events.retain(|e| e.timestamp_ms > before_ms);
    }
}

impl Default for ThreatCorrelator {
    fn default() -> Self {
        Self::new()
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_threat_correlation() {
        let mut correlator = ThreatCorrelator::new();

        // Record coordinated spoofing events
        for i in 0..5 {
            correlator.record_event(ThreatEvent {
                icao24: 0x100000 + i,
                event_type: ThreatEventType::Spoofing,
                timestamp_ms: 1000 + (i as u64) * 100,
                severity: 0.8,
                metadata: HashMap::new(),
            });
        }

        let clusters = correlator.correlate();
        assert!(!clusters.is_empty());
        assert!(clusters[0].pattern.contains("COORDINATED"));
    }
}
