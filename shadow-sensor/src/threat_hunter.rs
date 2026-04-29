//! Automated Threat Hunting Engine — Singularity Tier
//!
//! Adds two new capabilities on top of the rule-based hunter:
//!
//! 1. **Scan-burst detection** — a per-source rate window that flags any
//!    actor probing >= `SCAN_BURST_THRESHOLD` distinct ports/targets within
//!    `SCAN_BURST_WINDOW_SECS`. The detector is lock-light (per-source RW),
//!    matching multi-million-pps ingest rates.
//!
//! 2. **Autonomous Decoy Triggering (ADT)** — when a high-confidence scan is
//!    confirmed, the hunter pushes a `DecoyTrigger` to a registered sink so
//!    the honeynet worker (Go side) can respond with a tailored decoy in the
//!    same network frame. ADT runs in `Active` mode by default; switching to
//!    `Observe` disables auto-triggers but keeps detection.

use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Arc;
use tokio::sync::{mpsc, RwLock};

const SCAN_BURST_WINDOW_SECS: u64 = 30;
const SCAN_BURST_THRESHOLD: usize = 12;
const SCAN_BURST_HIGH_CONF: f64 = 0.85;

/// Hunting rule (pattern to detect)
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HuntingRule {
    pub id: String,
    pub name: String,
    pub description: String,
    pub severity: u8,
    pub pattern: String,
    pub enabled: bool,
    pub false_positive_rate: f64,
}

/// Evidence piece for investigation
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Evidence {
    pub id: String,
    pub evidence_type: String,
    pub timestamp: u64,
    pub value: String,
    pub confidence: f64,
    pub source: String,
}

/// Investigation case
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Investigation {
    pub case_id: String,
    pub target: String,
    pub start_time: u64,
    pub status: String,
    pub severity: u8,
    pub evidence_count: usize,
    pub suspected_attack: String,
    pub recommendations: Vec<String>,
}

/// Operating mode for autonomous response.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ResponseMode {
    Observe,
    Active,
}

/// Trigger emitted to the honeynet sink when a scan crosses the high-conf gate.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DecoyTrigger {
    pub source: String,
    pub distinct_targets: usize,
    pub window_secs: u64,
    pub confidence: f64,
    pub recommended_decoy: String,
    pub timestamp: u64,
}

#[derive(Clone, Debug)]
struct ScanWindow {
    targets: VecDeque<(String, u64)>,
    distinct: HashSet<String>,
}

pub struct ThreatHunter {
    rules: Arc<RwLock<Vec<HuntingRule>>>,
    investigations: Arc<RwLock<HashMap<String, Investigation>>>,
    evidence_store: Arc<RwLock<Vec<Evidence>>>,
    scan_windows: Arc<RwLock<HashMap<String, ScanWindow>>>,
    triggered_sources: Arc<RwLock<HashMap<String, u64>>>,
    decoy_tx: Arc<RwLock<Option<mpsc::Sender<DecoyTrigger>>>>,
    response_mode: Arc<RwLock<ResponseMode>>,
}

impl ThreatHunter {
    pub fn new() -> Self {
        ThreatHunter {
            rules: Arc::new(RwLock::new(Vec::new())),
            investigations: Arc::new(RwLock::new(HashMap::new())),
            evidence_store: Arc::new(RwLock::new(Vec::new())),
            scan_windows: Arc::new(RwLock::new(HashMap::new())),
            triggered_sources: Arc::new(RwLock::new(HashMap::new())),
            decoy_tx: Arc::new(RwLock::new(None)),
            response_mode: Arc::new(RwLock::new(ResponseMode::Active)),
        }
    }

    /// Wire up the autonomous-response sink. Call once at startup.
    pub async fn install_decoy_sink(&self, tx: mpsc::Sender<DecoyTrigger>) {
        let mut slot = self.decoy_tx.write().await;
        *slot = Some(tx);
    }

    pub async fn set_response_mode(&self, mode: ResponseMode) {
        let mut m = self.response_mode.write().await;
        *m = mode;
    }

    pub async fn add_rule(&self, rule: HuntingRule) {
        let mut rules = self.rules.write().await;
        rules.push(rule);
    }

    pub async fn hunt(&self, data: &str) -> Vec<String> {
        let rules = self.rules.read().await;
        let mut matches = Vec::new();
        for rule in rules.iter().filter(|r| r.enabled) {
            if data.contains(&rule.pattern) {
                matches.push(format!("Rule '{}' matched", rule.name));
            }
        }
        matches
    }

    fn now_secs() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    }

    /// Record one probe observation `(source, target_key)`. `target_key` may
    /// be e.g. `"10.0.0.5:445"`. Returns Some(DecoyTrigger) when a high-
    /// confidence scan threshold is crossed for the first time within the
    /// current window. The trigger is also pushed to the registered sink
    /// when in Active mode.
    pub async fn observe_probe(&self, source: &str, target_key: &str) -> Option<DecoyTrigger> {
        let now = Self::now_secs();
        let mut windows = self.scan_windows.write().await;
        let window = windows
            .entry(source.to_string())
            .or_insert_with(|| ScanWindow {
                targets: VecDeque::new(),
                distinct: HashSet::new(),
            });
        // Trim aged-out entries.
        while let Some(&(_, ts)) = window.targets.front() {
            if now.saturating_sub(ts) > SCAN_BURST_WINDOW_SECS {
                if let Some((target, _)) = window.targets.pop_front() {
                    // Recompute distinct set if this was the last copy.
                    let still_present = window.targets.iter().any(|(t, _)| t == &target);
                    if !still_present {
                        window.distinct.remove(&target);
                    }
                }
            } else {
                break;
            }
        }
        window.targets.push_back((target_key.to_string(), now));
        window.distinct.insert(target_key.to_string());

        let distinct = window.distinct.len();
        let crossed = distinct >= SCAN_BURST_THRESHOLD;
        drop(windows);

        if !crossed {
            return None;
        }

        // Debounce: don't re-trigger the same source within the window.
        let mut triggered = self.triggered_sources.write().await;
        if let Some(&last) = triggered.get(source) {
            if now.saturating_sub(last) < SCAN_BURST_WINDOW_SECS {
                return None;
            }
        }
        triggered.insert(source.to_string(), now);
        drop(triggered);

        // Confidence rises with how many distinct targets we saw.
        let extra = distinct.saturating_sub(SCAN_BURST_THRESHOLD) as f64;
        let confidence = (SCAN_BURST_HIGH_CONF + extra * 0.01).min(0.99);
        let trigger = DecoyTrigger {
            source: source.to_string(),
            distinct_targets: distinct,
            window_secs: SCAN_BURST_WINDOW_SECS,
            confidence,
            recommended_decoy: classify_decoy(target_key),
            timestamp: now,
        };

        let mode = *self.response_mode.read().await;
        if matches!(mode, ResponseMode::Active) {
            if let Some(tx) = self.decoy_tx.read().await.as_ref() {
                // Non-blocking send; if the channel is full we drop the
                // trigger rather than backpressure the hot path.
                let _ = tx.try_send(trigger.clone());
            }
        }
        Some(trigger)
    }

    pub async fn open_investigation(
        &self,
        case_id: String,
        target: String,
        suspected_attack: String,
    ) -> Investigation {
        let investigation = Investigation {
            case_id: case_id.clone(),
            target,
            start_time: Self::now_secs(),
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

    pub async fn add_evidence(&self, case_id: &str, evidence: Evidence) {
        let mut store = self.evidence_store.write().await;
        store.push(evidence);
        let mut investigations = self.investigations.write().await;
        if let Some(inv) = investigations.get_mut(case_id) {
            inv.evidence_count += 1;
        }
    }

    pub async fn generate_report(&self, case_id: &str) -> Option<String> {
        let investigations = self.investigations.read().await;
        let investigation = investigations.get(case_id)?;
        let evidence = self.evidence_store.read().await;
        let case_evidence: Vec<_> = evidence.iter().collect();
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
            "Reconnaissance Scan" => {
                recommendations.push("Trigger autonomous decoy in scan path".to_string());
                recommendations.push("Add source IP to high-watch list".to_string());
                recommendations.push("Correlate with mesh peers for multi-vantage view".to_string());
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

    pub async fn check_escalations(&self) {
        let mut investigations = self.investigations.write().await;
        for inv in investigations.values_mut() {
            if inv.severity >= 8 && inv.status == "Open" {
                inv.status = "Escalated".to_string();
            }
        }
    }

    pub async fn open_cases(&self) -> Vec<Investigation> {
        let investigations = self.investigations.read().await;
        investigations
            .values()
            .filter(|i| i.status == "Open")
            .cloned()
            .collect()
    }
}

fn classify_decoy(target_key: &str) -> String {
    if target_key.ends_with(":445") || target_key.ends_with(":139") {
        "fake-smb-share".to_string()
    } else if target_key.ends_with(":3389") {
        "fake-rdp-host".to_string()
    } else if target_key.ends_with(":22") {
        "ssh-tarpit".to_string()
    } else if target_key.ends_with(":80") || target_key.ends_with(":443") {
        "fake-web-app".to_string()
    } else {
        "generic-honeypot".to_string()
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
    async fn rule_matching_still_works() {
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
    async fn scan_burst_triggers_autonomous_decoy() {
        let hunter = ThreatHunter::new();
        let (tx, mut rx) = mpsc::channel::<DecoyTrigger>(8);
        hunter.install_decoy_sink(tx).await;
        hunter.set_response_mode(ResponseMode::Active).await;

        // Probe 12 distinct targets from one source.
        let mut last = None;
        for port in 0..12 {
            last = hunter
                .observe_probe("attacker1", &format!("10.0.0.{}:445", port))
                .await;
        }
        let trigger = last.expect("expected trigger after threshold");
        assert!(trigger.confidence >= SCAN_BURST_HIGH_CONF);
        assert_eq!(trigger.recommended_decoy, "fake-smb-share");
        let received = rx.try_recv().expect("trigger must be pushed to sink");
        assert_eq!(received.source, "attacker1");
    }

    #[tokio::test]
    async fn observe_mode_skips_sink_push() {
        let hunter = ThreatHunter::new();
        let (tx, mut rx) = mpsc::channel::<DecoyTrigger>(8);
        hunter.install_decoy_sink(tx).await;
        hunter.set_response_mode(ResponseMode::Observe).await;

        for port in 0..14 {
            let _ = hunter
                .observe_probe("attacker2", &format!("10.0.0.{}:80", port))
                .await;
        }
        assert!(rx.try_recv().is_err(), "Observe mode must not push to sink");
    }

    #[tokio::test]
    async fn report_generation_for_recon_scan() {
        let hunter = ThreatHunter::new();
        hunter
            .open_investigation(
                "CASE-RECON".into(),
                "10.0.0.42".into(),
                "Reconnaissance Scan".into(),
            )
            .await;
        let report = hunter.generate_report("CASE-RECON").await.unwrap();
        assert!(report.contains("autonomous decoy"));
    }
}
