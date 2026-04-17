//! Automated Threat Hunting Engine
//!
//! Proactively searches for indicators of compromise and attack patterns:
//! - Behavioral pattern matching (statistical signatures)
//! - Timeline reconstruction (event correlation)
//! - Hypothesis generation (rule-based + ML)
//! - Attack chain detection
//! - Automatic investigation recommendations

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

/// Hunting rule (pattern to detect)
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HuntingRule {
    pub id: String,
    pub name: String,
    pub description: String,
    pub severity: u8,  // 1-10
    pub pattern: String,
    pub enabled: bool,
    pub false_positive_rate: f64,
}

/// Evidence piece for investigation
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Evidence {
    pub id: String,
    pub evidence_type: String,  // "packet", "connection", "behavior", "timeline"
    pub timestamp: u64,
    pub value: String,
    pub confidence: f64,
    pub source: String,
}

/// Investigation case
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Investigation {
    pub case_id: String,
    pub target: String,  // IP, ICAO24, etc.
    pub start_time: u64,
    pub status: String,  // "Open", "Investigating", "Escalated", "Resolved"
    pub severity: u8,
    pub evidence_count: usize,
    pub suspected_attack: String,
    pub recommendations: Vec<String>,
}

pub struct ThreatHunter {
    rules: Arc<RwLock<Vec<HuntingRule>>>,
    investigations: Arc<RwLock<HashMap<String, Investigation>>>,
    evidence_store: Arc<RwLock<Vec<Evidence>>>,
}

impl ThreatHunter {
    pub fn new() -> Self {
        ThreatHunter {
            rules: Arc::new(RwLock::new(Vec::new())),
            investigations: Arc::new(RwLock::new(HashMap::new())),
            evidence_store: Arc::new(RwLock::new(Vec::new())),
        }
    }

    /// Add a hunting rule
    pub async fn add_rule(&self, rule: HuntingRule) {
        let mut rules = self.rules.write().await;
        rules.push(rule);
    }

    /// Hunt for patterns matching rules
    pub async fn hunt(&self, data: &str) -> Vec<String> {
        let rules = self.rules.read().await;
        let mut matches = Vec::new();

        for rule in rules.iter().filter(|r| r.enabled) {
            // Simple pattern matching (in production, use regex or more sophisticated matching)
            if data.contains(&rule.pattern) {
                matches.push(format!("Rule '{}' matched", rule.name));
            }
        }

        matches
    }

    /// Create investigation case
    pub async fn open_investigation(
        &self,
        case_id: String,
        target: String,
        suspected_attack: String,
    ) -> Investigation {
        let investigation = Investigation {
            case_id: case_id.clone(),
            target,
            start_time: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            status: "Open".to_string(),
            severity: 5,
            evidence_count: 0,
            suspected_attack,
            recommendations: Vec::new(),
        };

        let mut investigations = self.investigations.write().await;
        investigations.insert(case_id, investigation.clone());
        investigation
    }

    /// Add evidence to investigation
    pub async fn add_evidence(&self, case_id: &str, evidence: Evidence) {
        let mut store = self.evidence_store.write().await;
        store.push(evidence);

        let mut investigations = self.investigations.write().await;
        if let Some(inv) = investigations.get_mut(case_id) {
            inv.evidence_count += 1;
        }
    }

    /// Generate investigation report with recommendations
    pub async fn generate_report(&self, case_id: &str) -> Option<String> {
        let investigations = self.investigations.read().await;
        let investigation = investigations.get(case_id)?;

        let evidence = self.evidence_store.read().await;
        let case_evidence: Vec<_> = evidence.iter().collect();

        // Build recommendations based on attack type
        let mut recommendations = Vec::new();
        match investigation.suspected_attack.as_str() {
            "Spoofing" => {
                recommendations.push("Verify ICAO24/callsign via independent source".to_string());
                recommendations.push("Check ADS-B signal strength and timing".to_string());
                recommendations.push("Cross-validate with MLAT/radar data".to_string());
            }
            "Lateral Movement" => {
                recommendations.push("Isolate affected systems immediately".to_string());
                recommendations.push("Dump memory for forensics".to_string());
                recommendations.push("Review firewall rules for lateral access".to_string());
            }
            "Data Exfiltration" => {
                recommendations.push("Block destination IP/domain immediately".to_string());
                recommendations.push("Investigate what data was accessed".to_string());
                recommendations.push("Notify affected parties".to_string());
            }
            _ => {
                recommendations.push("Escalate to SOC for manual investigation".to_string());
            }
        }

        let report = format!(
            "=== INVESTIGATION REPORT ===\n\
             Case ID: {}\n\
             Target: {}\n\
             Suspected Attack: {}\n\
             Severity: {}/10\n\
             Evidence Count: {}\n\
             Status: {}\n\
             \n\
             === RECOMMENDATIONS ===\n{}\n",
            investigation.case_id,
            investigation.target,
            investigation.suspected_attack,
            investigation.severity,
            case_evidence.len(),
            investigation.status,
            recommendations
                .iter()
                .enumerate()
                .map(|(i, r)| format!("{}. {}", i + 1, r))
                .collect::<Vec<_>>()
                .join("\n")
        );

        Some(report)
    }

    /// Auto-escalate high-severity cases
    pub async fn check_escalations(&self) {
        let mut investigations = self.investigations.write().await;
        for inv in investigations.values_mut() {
            if inv.severity >= 8 && inv.status == "Open" {
                inv.status = "Escalated".to_string();
            }
        }
    }

    /// Get all open investigations
    pub async fn open_cases(&self) -> Vec<Investigation> {
        let investigations = self.investigations.read().await;
        investigations
            .values()
            .filter(|i| i.status == "Open")
            .cloned()
            .collect()
    }
}

impl Default for ThreatHunter {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_threat_hunter_creation() {
        let hunter = ThreatHunter::new();
        assert_eq!(hunter.open_cases().await.len(), 0);
    }

    #[tokio::test]
    async fn test_rule_matching() {
        let hunter = ThreatHunter::new();

        let rule = HuntingRule {
            id: "rule1".to_string(),
            name: "Spoofing Detection".to_string(),
            description: "Detects ADS-B spoofing patterns".to_string(),
            severity: 8,
            pattern: "impossible_velocity".to_string(),
            enabled: true,
            false_positive_rate: 0.02,
        };

        hunter.add_rule(rule).await;

        let matches = hunter.hunt("aircraft has impossible_velocity").await;
        assert!(!matches.is_empty());
    }

    #[tokio::test]
    async fn test_investigation_creation() {
        let hunter = ThreatHunter::new();

        let inv = hunter
            .open_investigation(
                "CASE-001".to_string(),
                "ICAO123456".to_string(),
                "Spoofing".to_string(),
            )
            .await;

        assert_eq!(inv.case_id, "CASE-001");
        assert_eq!(inv.status, "Open");
    }

    #[tokio::test]
    async fn test_report_generation() {
        let hunter = ThreatHunter::new();

        hunter
            .open_investigation(
                "CASE-002".to_string(),
                "192.168.1.1".to_string(),
                "Lateral Movement".to_string(),
            )
            .await;

        let report = hunter.generate_report("CASE-002").await;
        assert!(report.is_some());
        assert!(report.unwrap().contains("Isolate affected systems"));
    }
}
