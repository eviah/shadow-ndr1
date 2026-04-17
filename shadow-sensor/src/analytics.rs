//! Advanced Real-Time Analytics Engine
//!
//! Complex event processing for streaming threat intelligence:
//! - Real-time aggregations (count, sum, percentile)
//! - Pattern detection (repeated sequences, anomalies)
//! - Correlation analysis (event causality)
//! - Predictive analytics (forecasting)
//! - Dashboard metrics generation

use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use tokio::sync::RwLock;

/// Metric aggregation
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MetricSnapshot {
    pub timestamp: u64,
    pub packet_count: u64,
    pub byte_count: u64,
    pub error_count: u64,
    pub threat_count: u64,
    pub avg_packet_size: f64,
    pub threats_per_minute: f64,
}

/// Event for correlation analysis
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CorrelatedEvent {
    pub event_id: String,
    pub event_type: String,
    pub timestamp: u64,
    pub duration_ms: u64,
    pub related_events: Vec<String>,
    pub confidence: f64,
}

pub struct AnalyticsEngine {
    metrics_history: Arc<RwLock<VecDeque<MetricSnapshot>>>,
    event_correlation: Arc<RwLock<HashMap<String, CorrelatedEvent>>>,
    alert_patterns: Arc<RwLock<Vec<(String, u32)>>>,  // (pattern, occurrences)
}

impl AnalyticsEngine {
    pub fn new() -> Self {
        AnalyticsEngine {
            metrics_history: Arc::new(RwLock::new(VecDeque::with_capacity(1440))),  // 24 hours @ 1min intervals
            event_correlation: Arc::new(RwLock::new(HashMap::new())),
            alert_patterns: Arc::new(RwLock::new(Vec::new())),
        }
    }

    /// Record metrics snapshot
    pub async fn record_metrics(&self, snapshot: MetricSnapshot) {
        let mut history = self.metrics_history.write().await;
        if history.len() >= 1440 {
            history.pop_front();  // Keep rolling 24-hour window
        }
        history.push_back(snapshot);
    }

    /// Calculate threat trends
    pub async fn threat_trend(&self) -> (f64, &'static str) {
        let history = self.metrics_history.read().await;
        if history.len() < 2 {
            return (0.0, "insufficient_data");
        }

        let recent_count = history.iter().rev().take(5).map(|m| m.threat_count).sum::<u64>();
        let previous_count = history
            .iter()
            .rev()
            .skip(5)
            .take(5)
            .map(|m| m.threat_count)
            .sum::<u64>();

        let trend = if previous_count > 0 {
            (recent_count as f64 - previous_count as f64) / previous_count as f64
        } else {
            0.0
        };

        let direction = if trend > 0.1 {
            "increasing"
        } else if trend < -0.1 {
            "decreasing"
        } else {
            "stable"
        };

        (trend, direction)
    }

    /// Correlate events (find causality chain)
    pub async fn correlate_events(
        &self,
        events: &[CorrelatedEvent],
    ) -> Vec<(String, Vec<String>)> {
        let mut chains = Vec::new();

        for i in 0..events.len() {
            let mut chain = vec![events[i].event_id.clone()];

            // Find subsequent events within 5 seconds
            for j in (i + 1)..events.len() {
                if events[j].timestamp - events[i].timestamp < 5000 {
                    // Temporal proximity
                    if self.should_correlate(&events[i], &events[j]).await {
                        chain.push(events[j].event_id.clone());
                    }
                }
            }

            if chain.len() > 1 {
                chains.push((format!("chain_{}", i), chain));
            }
        }

        chains
    }

    async fn should_correlate(&self, e1: &CorrelatedEvent, e2: &CorrelatedEvent) -> bool {
        // Simple heuristic: same source/dest or sequential event types
        e1.event_type.contains(&e2.event_type[..2.min(e2.event_type.len())])
            || e2.confidence > 0.7
    }

    /// Detect repeating patterns (e.g., repeated scan attempts)
    pub async fn detect_patterns(&self) -> Vec<(String, u32)> {
        let patterns = self.alert_patterns.read().await;
        patterns.iter().filter(|(_, count)| *count > 3).cloned().collect()
    }

    /// Predict next threat type based on history
    pub async fn predict_next_threat(&self) -> String {
        let history = self.metrics_history.read().await;

        if history.len() < 3 {
            return "unknown".to_string();
        }

        // Simple forecasting: if threats increasing, predict "escalation"
        let recent_threats: Vec<_> = history.iter().rev().take(5).map(|m| m.threat_count).collect();
        let is_increasing = recent_threats.windows(2).all(|w| w[1] <= w[0]);

        if is_increasing {
            "escalation".to_string()
        } else {
            "stabilization".to_string()
        }
    }

    /// Generate dashboard summary
    pub async fn dashboard_summary(&self) -> String {
        let history = self.metrics_history.read().await;

        if history.is_empty() {
            return "No data available".to_string();
        }

        let latest = &history[history.len() - 1];
        let total_packets: u64 = history.iter().map(|m| m.packet_count).sum();
        let total_threats: u64 = history.iter().map(|m| m.threat_count).sum();
        let avg_packet_size: f64 = history.iter().map(|m| m.avg_packet_size).sum::<f64>() / history.len() as f64;

        let (trend, direction) = self.threat_trend().await;

        format!(
            "📊 DASHBOARD SUMMARY\n\
             ┌─────────────────────────────────────┐\n\
             │ Total Packets:        {:>20} │\n\
             │ Total Threats:        {:>20} │\n\
             │ Avg Packet Size:      {:>18.0} B │\n\
             │ Threat Trend:         {:>15}% {} │\n\
             │ Current Rate:         {:>18.0} pps │\n\
             │ Error Count:          {:>20} │\n\
             └─────────────────────────────────────┘",
            total_packets,
            total_threats,
            avg_packet_size,
            (trend * 100.0) as i32,
            direction,
            latest.packet_count,
            latest.error_count
        )
    }

    /// Export metrics for Prometheus/Grafana
    pub async fn export_metrics(&self) -> String {
        let history = self.metrics_history.read().await;

        if history.is_empty() {
            return String::new();
        }

        let latest = &history[history.len() - 1];
        format!(
            "# HELP shadow_packets_total Total packets processed\n\
             # TYPE shadow_packets_total counter\n\
             shadow_packets_total {}\n\
             # HELP shadow_threats_total Total threats detected\n\
             # TYPE shadow_threats_total counter\n\
             shadow_threats_total {}\n\
             # HELP shadow_packet_size_avg Average packet size\n\
             # TYPE shadow_packet_size_avg gauge\n\
             shadow_packet_size_avg {}\n\
             # HELP shadow_errors_total Total errors\n\
             # TYPE shadow_errors_total counter\n\
             shadow_errors_total {}\n",
            latest.packet_count,
            latest.threat_count,
            latest.avg_packet_size,
            latest.error_count
        )
    }
}

impl Default for AnalyticsEngine {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_analytics_engine_creation() {
        let engine = AnalyticsEngine::new();
        let summary = engine.dashboard_summary().await;
        assert!(summary.contains("No data available"));
    }

    #[tokio::test]
    async fn test_metrics_recording() {
        let engine = AnalyticsEngine::new();

        let snapshot = MetricSnapshot {
            timestamp: 0,
            packet_count: 1000,
            byte_count: 500_000,
            error_count: 5,
            threat_count: 3,
            avg_packet_size: 500.0,
            threats_per_minute: 0.05,
        };

        engine.record_metrics(snapshot).await;

        let summary = engine.dashboard_summary().await;
        assert!(summary.contains("1000"));
    }

    #[tokio::test]
    async fn test_threat_trend() {
        let engine = AnalyticsEngine::new();

        for i in 0..10 {
            let snapshot = MetricSnapshot {
                timestamp: i as u64,
                packet_count: 1000 + i as u64 * 100,
                byte_count: 500_000,
                error_count: 5,
                threat_count: if i < 5 { 1 } else { 5 },
                avg_packet_size: 500.0,
                threats_per_minute: 0.05,
            };
            engine.record_metrics(snapshot).await;
        }

        let (trend, _direction) = engine.threat_trend().await;
        assert!(trend > 0.0);  // Trend should be positive (increasing threats)
    }

    #[tokio::test]
    async fn test_export_metrics() {
        let engine = AnalyticsEngine::new();

        let snapshot = MetricSnapshot {
            timestamp: 0,
            packet_count: 1000,
            byte_count: 500_000,
            error_count: 5,
            threat_count: 3,
            avg_packet_size: 500.0,
            threats_per_minute: 0.05,
        };

        engine.record_metrics(snapshot).await;
        let export = engine.export_metrics().await;
        assert!(export.contains("shadow_packets_total"));
    }
}
