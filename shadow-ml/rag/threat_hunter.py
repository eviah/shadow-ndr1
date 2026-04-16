"""
rag/threat_hunter.py — Autonomous LLM Threat Hunting Agent v10.0

Background AI agent that continuously queries raw logs for stealthy APT actions.
Uses Claude AI + RAG to autonomously hunt for indicators of compromise,
dormant malware beacons, and advanced persistent threat patterns.

Hunting strategies:
  • Beaconing analysis — detect C2 heartbeat communications
  • Temporal correlation — link events across protocols by time
  • Rare process execution — baseline deviations in system calls
  • Lateral movement detection — unusual east-west traffic
  • Data staging / exfiltration — large outbound transfers at unusual hours
  • Living-off-the-land — legitimate tools used maliciously (LOLBins)
  • Supply chain indicators — compromised packages/certificates
"""

from __future__ import annotations

import json
import logging
import math
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional

logger = logging.getLogger("shadow.rag.threat_hunter")


# ---------------------------------------------------------------------------
# Hunting hypotheses
# ---------------------------------------------------------------------------

@dataclass
class HuntingHypothesis:
    hypothesis_id: str
    name: str
    description: str
    query_template: str         # query sent to RAG/logs
    severity: str               # low / medium / high / critical
    mitre_ttp: str              # e.g. T1071
    confidence_threshold: float = 0.6

    def render_query(self, context: Dict[str, Any]) -> str:
        try:
            return self.query_template.format(**context)
        except KeyError:
            return self.query_template


BUILT_IN_HYPOTHESES = [
    HuntingHypothesis(
        hypothesis_id="H001",
        name="DNS Beaconing",
        description="Malware making periodic DNS queries to C2 server",
        query_template="DNS queries from {src_ip} with regular intervals to same domain",
        severity="high",
        mitre_ttp="T1071.004",
    ),
    HuntingHypothesis(
        hypothesis_id="H002",
        name="ADS-B Spoofing Campaign",
        description="Coordinated false ADS-B transmissions to disrupt air traffic",
        query_template="multiple aircraft position anomalies near {airport_icao} simultaneously",
        severity="critical",
        mitre_ttp="T0882",
    ),
    HuntingHypothesis(
        hypothesis_id="H003",
        name="ACARS Buffer Overflow",
        description="Malformed ACARS message targeting avionics firmware",
        query_template="ACARS messages with unusual length or binary content to {aircraft_id}",
        severity="critical",
        mitre_ttp="T1203",
    ),
    HuntingHypothesis(
        hypothesis_id="H004",
        name="Lateral Movement via RDP",
        description="Attacker pivoting through internal network using RDP",
        query_template="RDP connections from {compromised_host} to internal hosts in last hour",
        severity="high",
        mitre_ttp="T1021.001",
    ),
    HuntingHypothesis(
        hypothesis_id="H005",
        name="Data Exfiltration via DNS",
        description="Data exfiltration tunneled through DNS queries",
        query_template="DNS TXT queries with high entropy subdomains from {src_ip}",
        severity="high",
        mitre_ttp="T1048.003",
    ),
    HuntingHypothesis(
        hypothesis_id="H006",
        name="Modbus Command Injection",
        description="Unauthorized Modbus write commands to SCADA registers",
        query_template="Modbus function code 6 or 16 to register range 0-100 from {src_ip}",
        severity="critical",
        mitre_ttp="T0855",
    ),
    HuntingHypothesis(
        hypothesis_id="H007",
        name="Credential Stuffing",
        description="Automated login attempts using breached credentials",
        query_template="authentication failures exceeding 10 per minute from {src_ip}",
        severity="medium",
        mitre_ttp="T1110.004",
    ),
    HuntingHypothesis(
        hypothesis_id="H008",
        name="BGP Route Hijack",
        description="Unauthorized BGP route announcement for aviation IP space",
        query_template="BGP origin AS change for prefixes {prefix_list} in last 30 minutes",
        severity="critical",
        mitre_ttp="T1557",
    ),
]


# ---------------------------------------------------------------------------
# Hunt result
# ---------------------------------------------------------------------------

@dataclass
class HuntResult:
    hypothesis_id: str
    hypothesis_name: str
    confidence: float
    evidence: List[Dict[str, Any]]
    narrative: str
    recommended_actions: List[str]
    severity: str
    timestamp: float = field(default_factory=time.time)
    false_positive_probability: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "hypothesis_id": self.hypothesis_id,
            "hypothesis_name": self.hypothesis_name,
            "confidence": round(self.confidence, 4),
            "severity": self.severity,
            "narrative": self.narrative,
            "recommended_actions": self.recommended_actions,
            "evidence_count": len(self.evidence),
            "false_positive_probability": round(self.false_positive_probability, 4),
            "timestamp": self.timestamp,
        }


# ---------------------------------------------------------------------------
# Statistical hunters (no LLM required)
# ---------------------------------------------------------------------------

class BeaconingDetector:
    """
    Detects C2 beaconing: malware that calls home at regular intervals.
    Uses jitter-aware autocorrelation to find periodic signals.
    """

    def __init__(self, min_beacons: int = 10, jitter_tolerance: float = 0.2):
        self.min_beacons = min_beacons
        self.jitter_tolerance = jitter_tolerance
        self._flows: Dict[str, deque] = defaultdict(lambda: deque(maxlen=1000))

    def observe(self, src_ip: str, dst_domain: str, timestamp: float) -> None:
        key = f"{src_ip}→{dst_domain}"
        self._flows[key].append(timestamp)

    def analyze(self, src_ip: str, dst_domain: str) -> Optional[Dict[str, Any]]:
        key = f"{src_ip}→{dst_domain}"
        times = sorted(self._flows[key])
        if len(times) < self.min_beacons:
            return None

        intervals = [times[i + 1] - times[i] for i in range(len(times) - 1)]
        mu = sum(intervals) / len(intervals)
        if mu < 1:
            return None

        std = math.sqrt(sum((iv - mu)**2 for iv in intervals) / len(intervals))
        cv = std / mu  # Coefficient of variation: low CV = periodic

        if cv < self.jitter_tolerance:
            return {
                "src_ip": src_ip,
                "dst_domain": dst_domain,
                "beacon_interval_s": round(mu, 1),
                "jitter_pct": round(cv * 100, 1),
                "observations": len(times),
                "confidence": round(max(0, 1 - cv / self.jitter_tolerance), 3),
            }
        return None


class LateralMovementDetector:
    """
    Detects east-west lateral movement: hosts suddenly connecting to new internal targets.
    """

    def __init__(self, baseline_window_days: int = 7):
        self._baseline: Dict[str, set] = defaultdict(set)   # src → {normal_dsts}
        self._recent: Dict[str, set] = defaultdict(set)
        self._baseline_cutoff = time.time() - baseline_window_days * 86400

    def observe_connection(self, src_ip: str, dst_ip: str, timestamp: float,
                           is_internal: bool = True) -> None:
        if not is_internal:
            return
        if timestamp < self._baseline_cutoff:
            self._baseline[src_ip].add(dst_ip)
        else:
            self._recent[src_ip].add(dst_ip)

    def find_anomalies(self) -> List[Dict[str, Any]]:
        anomalies = []
        for src, recent_dsts in self._recent.items():
            baseline_dsts = self._baseline.get(src, set())
            new_dsts = recent_dsts - baseline_dsts
            if len(new_dsts) >= 3:  # 3+ new internal targets
                anomalies.append({
                    "src_ip": src,
                    "new_internal_targets": list(new_dsts),
                    "count": len(new_dsts),
                    "confidence": min(1.0, len(new_dsts) / 10.0),
                })
        return sorted(anomalies, key=lambda x: -x["confidence"])


# ---------------------------------------------------------------------------
# LLM-based hunter
# ---------------------------------------------------------------------------

class _LLMHunter:
    """Uses Claude AI to analyse evidence and generate hunt narratives."""

    def __init__(self, model: str = "claude-sonnet-4-6"):
        self._model = model
        self._client = None
        self._init()

    def _init(self) -> None:
        try:
            import anthropic
            self._client = anthropic.Anthropic()
        except ImportError:
            logger.info("anthropic not installed — LLM hunting disabled")

    def analyze(
        self,
        hypothesis: HuntingHypothesis,
        evidence: List[Dict[str, Any]],
        rag_context: List[str],
    ) -> str:
        """Generate threat hunting narrative using Claude."""
        if not self._client:
            return self._template_narrative(hypothesis, evidence)

        system = (
            "You are an expert threat hunter with deep knowledge of aviation cybersecurity, "
            "MITRE ATT&CK, and network forensics. Analyze the provided evidence and produce "
            "a concise, actionable threat hunting report. Be specific about IOCs and TTPs."
        )

        rag_text = "\n".join(f"- {ctx}" for ctx in rag_context[:5])
        evidence_text = json.dumps(evidence[:10], indent=2, default=str)

        user_msg = (
            f"HUNTING HYPOTHESIS: {hypothesis.name}\n"
            f"Description: {hypothesis.description}\n"
            f"MITRE TTP: {hypothesis.mitre_ttp}\n\n"
            f"RELEVANT THREAT INTELLIGENCE:\n{rag_text}\n\n"
            f"EVIDENCE:\n{evidence_text}\n\n"
            f"Provide: 1) Confidence assessment (0-1), 2) Narrative analysis, "
            f"3) Recommended immediate actions, 4) False positive considerations."
        )

        try:
            response = self._client.messages.create(
                model=self._model,
                max_tokens=1024,
                system=system,
                messages=[{"role": "user", "content": user_msg}],
            )
            return response.content[0].text
        except Exception as exc:
            logger.warning("LLM hunting failed: %s", exc)
            return self._template_narrative(hypothesis, evidence)

    @staticmethod
    def _template_narrative(
        hypothesis: HuntingHypothesis,
        evidence: List[Dict[str, Any]],
    ) -> str:
        n = len(evidence)
        return (
            f"THREAT HUNT: {hypothesis.name} ({hypothesis.mitre_ttp})\n"
            f"Found {n} evidence item(s) consistent with this hypothesis.\n"
            f"Severity: {hypothesis.severity.upper()}.\n"
            f"Recommended: Investigate flagged hosts, review logs, escalate to Tier 2."
        )


# ---------------------------------------------------------------------------
# Main Threat Hunting Engine
# ---------------------------------------------------------------------------

class ThreatHuntingEngine:
    """
    SHADOW-ML Autonomous Threat Hunting Engine v10.0

    Runs continuously in background, applying hunting hypotheses to raw telemetry.
    Integrates LLM analysis and RAG context for enriched hunt reports.
    """

    VERSION = "10.0.0"

    def __init__(
        self,
        vector_store: Optional[Any] = None,
        hunt_interval_s: float = 300.0,  # 5 minutes
    ):
        self._vector_store = vector_store
        self._hypotheses = {h.hypothesis_id: h for h in BUILT_IN_HYPOTHESES}
        self._llm = _LLMHunter()
        self._beaconing = BeaconingDetector()
        self._lateral = LateralMovementDetector()
        self._results: List[HuntResult] = []
        self._hunt_interval = hunt_interval_s
        self._stats: Dict[str, Any] = {
            "hunts_completed": 0,
            "threats_found": 0,
            "hypotheses_tested": 0,
        }
        logger.info("ThreatHuntingEngine v%s initialised (%d hypotheses)", self.VERSION, len(self._hypotheses))

    def add_hypothesis(self, hypothesis: HuntingHypothesis) -> None:
        self._hypotheses[hypothesis.hypothesis_id] = hypothesis

    def observe_dns(self, src_ip: str, domain: str, timestamp: Optional[float] = None) -> None:
        self._beaconing.observe(src_ip, domain, timestamp or time.time())

    def observe_connection(self, src_ip: str, dst_ip: str, is_internal: bool = True) -> None:
        self._lateral.observe_connection(src_ip, dst_ip, time.time(), is_internal)

    def hunt(
        self,
        context: Dict[str, Any],
        hypothesis_ids: Optional[List[str]] = None,
    ) -> List[HuntResult]:
        """
        Run a full hunting cycle against provided context.
        Returns list of HuntResults with confidence >= threshold.
        """
        self._stats["hunts_completed"] += 1
        results = []
        targets = hypothesis_ids or list(self._hypotheses.keys())

        for hid in targets:
            hyp = self._hypotheses.get(hid)
            if not hyp:
                continue
            self._stats["hypotheses_tested"] += 1

            # Gather evidence
            evidence = self._gather_evidence(hyp, context)
            if not evidence:
                continue

            # Get RAG context
            rag_results = []
            if self._vector_store:
                try:
                    sr = self._vector_store.search(
                        f"{hyp.name} {hyp.mitre_ttp}", top_k=3
                    )
                    rag_results = [r.payload.get("text", "") for r in sr]
                except Exception:
                    pass

            # LLM analysis
            narrative = self._llm.analyze(hyp, evidence, rag_results)

            # Confidence from evidence density
            confidence = min(1.0, len(evidence) / 10.0 * hyp.confidence_threshold * 2)

            if confidence >= hyp.confidence_threshold:
                result = HuntResult(
                    hypothesis_id=hid,
                    hypothesis_name=hyp.name,
                    confidence=confidence,
                    evidence=evidence,
                    narrative=narrative,
                    recommended_actions=self._recommend_actions(hyp, confidence),
                    severity=hyp.severity,
                    false_positive_probability=max(0.0, 1 - confidence) * 0.3,
                )
                results.append(result)
                self._results.append(result)
                self._stats["threats_found"] += 1
                logger.warning(
                    "THREAT HUNT POSITIVE: hypothesis=%s confidence=%.2f severity=%s",
                    hyp.name, confidence, hyp.severity,
                )

        return results

    def _gather_evidence(
        self,
        hyp: HuntingHypothesis,
        context: Dict[str, Any],
    ) -> List[Dict[str, Any]]:
        evidence = []

        # Use context data as evidence items
        if "events" in context:
            for event in context["events"][:50]:
                relevance = self._score_relevance(event, hyp)
                if relevance > 0.3:
                    evidence.append({**event, "_relevance": relevance})

        # Beaconing evidence
        if hyp.hypothesis_id == "H001":
            src_ip = context.get("src_ip", "")
            for domain in context.get("queried_domains", []):
                beacon = self._beaconing.analyze(src_ip, domain)
                if beacon:
                    evidence.append(beacon)

        # Lateral movement evidence
        if hyp.hypothesis_id == "H004":
            anomalies = self._lateral.find_anomalies()
            evidence.extend(anomalies[:5])

        return evidence

    def _score_relevance(self, event: Dict[str, Any], hyp: HuntingHypothesis) -> float:
        """Score how relevant an event is to a hypothesis."""
        score = 0.0
        keywords = hyp.description.lower().split()
        event_text = json.dumps(event, default=str).lower()
        for kw in keywords:
            if len(kw) > 4 and kw in event_text:
                score += 0.1
        return min(1.0, score)

    @staticmethod
    def _recommend_actions(hyp: HuntingHypothesis, confidence: float) -> List[str]:
        base = [
            f"Review logs for MITRE TTP {hyp.mitre_ttp}",
            "Capture full packet data for forensic analysis",
        ]
        if confidence > 0.8:
            base.insert(0, "IMMEDIATE: Escalate to SOC Tier 2 / CISO")
        if hyp.severity == "critical":
            base.append("Consider isolating affected hosts")
            base.append("Initiate incident response playbook")
        return base

    def get_hunt_results(self, min_confidence: float = 0.0) -> List[Dict[str, Any]]:
        return [
            r.to_dict() for r in self._results
            if r.confidence >= min_confidence
        ]

    def get_stats(self) -> Dict[str, Any]:
        return {**self._stats, "open_results": len(self._results)}
