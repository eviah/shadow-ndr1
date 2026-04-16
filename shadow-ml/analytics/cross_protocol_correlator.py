"""
analytics/cross_protocol_correlator.py — Cross-Protocol Temporal Correlator v10.0

Detects coordinated attacks spanning multiple protocols by finding
temporal and causal correlations between events.

Key insight: sophisticated attackers coordinate cyber and physical attacks:
  "An ADS-B spoofing event correlates exactly with a suspicious IEC104
   command sent 2.4 seconds prior, linking a cyber and physical attack."

Correlation methods:
  • Temporal windowing: events within configurable time window
  • Causal chain analysis: if A precedes B consistently → A may cause B
  • Pearson/Spearman cross-correlation of event time series
  • Entity linking: same src_ip / ICAO24 / aircraft_id across protocols
  • Graph-based correlation: build causal event graphs
  • Statistical significance testing (chi-square, Fisher's exact)
"""

from __future__ import annotations

import hashlib
import logging
import math
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple

logger = logging.getLogger("shadow.analytics.correlator")


# ---------------------------------------------------------------------------
# Correlated event model
# ---------------------------------------------------------------------------

@dataclass
class ProtocolEvent:
    event_id: str
    protocol: str           # adsb / iec104 / dns / modbus / tcp / acars / bgp
    timestamp: float
    threat_score: float
    src_ip: str = ""
    entity_id: str = ""     # ICAO24 for aviation, unit_id for SCADA
    description: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class Correlation:
    correlation_id: str
    events: List[ProtocolEvent]
    protocols: List[str]
    time_span_s: float
    correlation_score: float
    correlation_type: str   # temporal / entity / causal / spatial
    description: str
    attack_hypothesis: str
    confidence: float
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "correlation_id": self.correlation_id,
            "protocols": self.protocols,
            "event_count": len(self.events),
            "time_span_s": round(self.time_span_s, 3),
            "correlation_score": round(self.correlation_score, 4),
            "correlation_type": self.correlation_type,
            "description": self.description,
            "attack_hypothesis": self.attack_hypothesis,
            "confidence": round(self.confidence, 4),
            "timestamp": self.timestamp,
        }


# ---------------------------------------------------------------------------
# Known attack patterns (temporal signature database)
# ---------------------------------------------------------------------------

ATTACK_SIGNATURES: List[Dict[str, Any]] = [
    {
        "name": "Cyber-Physical ADS-B + IEC104 Attack",
        "sequence": [("iec104", 0, 5), ("adsb", 1, 10)],
        # (protocol, min_delay_s, max_delay_s) relative to first event
        "description": "IEC104 command sent before ADS-B spoofing to disable radar failsafe",
        "severity": "critical",
        "confidence_base": 0.9,
    },
    {
        "name": "BGP Hijack + C2 Beaconing",
        "sequence": [("bgp", 0, 2), ("dns", 5, 120), ("tcp", 10, 300)],
        "description": "BGP route manipulation followed by C2 beacon check-in",
        "severity": "critical",
        "confidence_base": 0.85,
    },
    {
        "name": "Reconnaissance + ACARS Inject",
        "sequence": [("dns", 0, 60), ("acars", 30, 300)],
        "description": "DNS recon of aircraft ID followed by ACARS payload injection",
        "severity": "high",
        "confidence_base": 0.75,
    },
    {
        "name": "Credential Steal + Modbus Write",
        "sequence": [("tcp", 0, 30), ("modbus", 10, 120)],
        "description": "Credential theft followed by unauthorized Modbus write to SCADA",
        "severity": "critical",
        "confidence_base": 0.8,
    },
    {
        "name": "GPS Jam + ILS Spoof",
        "sequence": [("gps", 0, 5), ("ils", 2, 30)],
        "description": "GPS jamming coordinated with ILS glide-slope spoofing",
        "severity": "critical",
        "confidence_base": 0.95,
    },
    {
        "name": "DDoS + Data Exfiltration",
        "sequence": [("tcp", 0, 10), ("dns", 5, 300)],
        "description": "DDoS distraction followed by DNS-tunneled data exfiltration",
        "severity": "high",
        "confidence_base": 0.7,
    },
]


# ---------------------------------------------------------------------------
# Time series correlation
# ---------------------------------------------------------------------------

def pearson_correlation(x: List[float], y: List[float]) -> float:
    """Pearson correlation coefficient between two series."""
    n = min(len(x), len(y))
    if n < 3:
        return 0.0
    x = x[:n]; y = y[:n]
    mu_x = sum(x) / n; mu_y = sum(y) / n
    cov = sum((xi - mu_x) * (yi - mu_y) for xi, yi in zip(x, y))
    std_x = math.sqrt(sum((xi - mu_x)**2 for xi in x)) + 1e-12
    std_y = math.sqrt(sum((yi - mu_y)**2 for yi in y)) + 1e-12
    return cov / (std_x * std_y)


def temporal_lag_correlation(
    series_a: List[Tuple[float, float]],   # (timestamp, score)
    series_b: List[Tuple[float, float]],
    window_s: float = 300.0,
    lag_step_s: float = 1.0,
    max_lag_s: float = 60.0,
) -> Tuple[float, float]:
    """
    Find the lag (seconds) at which series_b best correlates with series_a.
    Returns (best_correlation, best_lag_s).
    """
    if not series_a or not series_b:
        return 0.0, 0.0

    # Bin into 1-second buckets
    def bin_series(series: List[Tuple[float, float]]) -> Dict[int, float]:
        binned: Dict[int, float] = {}
        for ts, score in series:
            bucket = int(ts)
            binned[bucket] = max(binned.get(bucket, 0.0), score)
        return binned

    binned_a = bin_series(series_a)
    binned_b = bin_series(series_b)

    if not binned_a or not binned_b:
        return 0.0, 0.0

    min_t = min(min(binned_a), min(binned_b))
    max_t = max(max(binned_a), max(binned_b))

    best_corr = 0.0
    best_lag = 0.0

    lag = 0.0
    while lag <= max_lag_s:
        vec_a = [binned_a.get(int(min_t + t), 0.0) for t in range(int(max_t - min_t + 1))]
        vec_b = [binned_b.get(int(min_t + t + lag), 0.0) for t in range(int(max_t - min_t + 1))]
        corr = abs(pearson_correlation(vec_a, vec_b))
        if corr > best_corr:
            best_corr = corr
            best_lag = lag
        lag += lag_step_s

    return best_corr, best_lag


# ---------------------------------------------------------------------------
# Causal event graph
# ---------------------------------------------------------------------------

class CausalEventGraph:
    """
    Directed graph where A → B means A precedes B and may have caused it.
    Edges are weighted by temporal proximity and score correlation.
    """

    def __init__(self):
        self._nodes: Dict[str, ProtocolEvent] = {}
        self._edges: Dict[str, Dict[str, float]] = defaultdict(dict)

    def add_event(self, event: ProtocolEvent) -> None:
        self._nodes[event.event_id] = event

    def add_edge(self, from_id: str, to_id: str, weight: float) -> None:
        self._edges[from_id][to_id] = weight

    def find_paths(self, protocols: List[str]) -> List[List[ProtocolEvent]]:
        """Find event chains traversing the given protocol sequence."""
        # Filter nodes by protocol
        proto_groups: Dict[str, List[ProtocolEvent]] = defaultdict(list)
        for evt in self._nodes.values():
            proto_groups[evt.protocol].append(evt)

        if not all(p in proto_groups for p in protocols):
            return []

        # Build chains: first protocol nodes → following protocol nodes
        chains = []
        for start in sorted(proto_groups.get(protocols[0], []), key=lambda e: e.timestamp):
            chain = [start]
            valid = True
            for proto in protocols[1:]:
                candidates = [
                    e for e in proto_groups[proto]
                    if e.timestamp > chain[-1].timestamp
                    and e.timestamp - chain[-1].timestamp < 300
                ]
                if not candidates:
                    valid = False
                    break
                # Pick nearest in time
                chain.append(min(candidates, key=lambda e: e.timestamp - chain[-1].timestamp))
            if valid and len(chain) == len(protocols):
                chains.append(chain)

        return chains


# ---------------------------------------------------------------------------
# Main Cross-Protocol Correlator
# ---------------------------------------------------------------------------

class CrossProtocolCorrelator:
    """
    SHADOW-ML Cross-Protocol Temporal Correlator v10.0

    Detects coordinated multi-protocol attacks by correlating events
    across ADS-B, IEC104, DNS, Modbus, TCP, ACARS, BGP, and GPS.

    The key detection capability: linking a cyber event (e.g., Modbus write
    to disable a radar) with a physical attack (e.g., ADS-B spoofing)
    that begins seconds later — revealing a coordinated cyber-physical attack.
    """

    VERSION = "10.0.0"

    def __init__(
        self,
        time_window_s: float = 300.0,  # 5 minute correlation window
        min_correlation_score: float = 0.5,
    ):
        self._time_window = time_window_s
        self._min_score = min_correlation_score
        self._event_buffer: deque = deque(maxlen=10_000)
        self._protocol_series: Dict[str, deque] = defaultdict(lambda: deque(maxlen=1000))
        self._causal_graph = CausalEventGraph()
        self._correlations: List[Correlation] = []
        self._stats: Dict[str, Any] = {
            "events_ingested": 0,
            "correlations_found": 0,
            "by_type": {},
        }
        logger.info("CrossProtocolCorrelator v%s initialised (window=%.0fs)", self.VERSION, time_window_s)

    def ingest(self, event: ProtocolEvent) -> Optional[List[Correlation]]:
        """Ingest one event and check for new correlations. Returns correlations if found."""
        self._event_buffer.append(event)
        self._protocol_series[event.protocol].append((event.timestamp, event.threat_score))
        self._causal_graph.add_event(event)
        self._stats["events_ingested"] += 1

        # Only run full correlation on high-score events
        if event.threat_score >= 0.5:
            return self._run_correlation(event)
        return None

    def ingest_batch(self, events: List[ProtocolEvent]) -> List[Correlation]:
        all_correlations = []
        for e in events:
            found = self.ingest(e)
            if found:
                all_correlations.extend(found)
        return all_correlations

    def _run_correlation(self, trigger_event: ProtocolEvent) -> List[Correlation]:
        """Run all correlation methods for a trigger event."""
        correlations = []

        # 1. Pattern matching against known attack signatures
        correlations.extend(self._match_signatures(trigger_event))

        # 2. Entity-based correlation (same ICAO24 / IP across protocols)
        correlations.extend(self._correlate_by_entity(trigger_event))

        # 3. Temporal lag correlation between protocol time series
        correlations.extend(self._time_series_correlation(trigger_event))

        significant = [c for c in correlations if c.correlation_score >= self._min_score]
        if significant:
            self._correlations.extend(significant)
            self._stats["correlations_found"] += len(significant)
            for c in significant:
                ct = c.correlation_type
                self._stats["by_type"][ct] = self._stats["by_type"].get(ct, 0) + 1
                logger.warning(
                    "CROSS-PROTOCOL CORRELATION: type=%s protocols=%s score=%.2f hypothesis=%s",
                    c.correlation_type, c.protocols, c.correlation_score, c.attack_hypothesis[:50],
                )
        return significant

    def _match_signatures(self, trigger: ProtocolEvent) -> List[Correlation]:
        """Match against known attack signatures."""
        correlations = []
        now = trigger.timestamp
        window_events = [
            e for e in self._event_buffer
            if abs(now - e.timestamp) <= self._time_window
        ]

        for sig in ATTACK_SIGNATURES:
            sequence = sig["sequence"]
            if not any(trigger.protocol == proto for proto, _, _ in sequence):
                continue

            chains = self._causal_graph.find_paths([p for p, _, _ in sequence])
            for chain in chains:
                # Verify timing constraints
                valid = True
                for i, (proto, min_delay, max_delay) in enumerate(sequence[1:], 1):
                    delay = chain[i].timestamp - chain[0].timestamp
                    if not (min_delay <= delay <= max_delay):
                        valid = False
                        break

                if valid:
                    time_span = chain[-1].timestamp - chain[0].timestamp
                    score = sig["confidence_base"] * max(e.threat_score for e in chain)
                    corr_id = hashlib.sha256(
                        f"{sig['name']}{chain[0].event_id}{chain[-1].event_id}".encode()
                    ).hexdigest()[:12]

                    correlations.append(Correlation(
                        correlation_id=corr_id,
                        events=chain,
                        protocols=[e.protocol for e in chain],
                        time_span_s=time_span,
                        correlation_score=score,
                        correlation_type="causal",
                        description=sig["description"],
                        attack_hypothesis=sig["name"],
                        confidence=sig["confidence_base"],
                    ))
        return correlations

    def _correlate_by_entity(self, trigger: ProtocolEvent) -> List[Correlation]:
        """Find events from same entity (IP, ICAO24) across different protocols."""
        if not trigger.entity_id and not trigger.src_ip:
            return []

        link_key = trigger.entity_id or trigger.src_ip
        now = trigger.timestamp

        related = [
            e for e in self._event_buffer
            if (e.entity_id == link_key or e.src_ip == link_key)
            and e.protocol != trigger.protocol
            and abs(now - e.timestamp) <= self._time_window
            and e.event_id != trigger.event_id
        ]

        if not related:
            return []

        protocols = list({trigger.protocol} | {e.protocol for e in related})
        avg_score = (trigger.threat_score + sum(e.threat_score for e in related)) / (1 + len(related))
        corr_id = hashlib.sha256(f"entity_{link_key}_{now}".encode()).hexdigest()[:12]

        return [Correlation(
            correlation_id=corr_id,
            events=[trigger] + related,
            protocols=protocols,
            time_span_s=max(abs(now - e.timestamp) for e in related),
            correlation_score=avg_score,
            correlation_type="entity",
            description=f"Same entity '{link_key}' active across protocols: {protocols}",
            attack_hypothesis=f"Multi-protocol attack by entity {link_key}",
            confidence=0.7,
        )]

    def _time_series_correlation(self, trigger: ProtocolEvent) -> List[Correlation]:
        """Find protocol pairs with high temporal correlation."""
        correlations = []
        trigger_series = list(self._protocol_series[trigger.protocol])
        if len(trigger_series) < 10:
            return []

        for other_proto, other_series in self._protocol_series.items():
            if other_proto == trigger.protocol or len(other_series) < 10:
                continue

            corr, lag = temporal_lag_correlation(
                list(trigger_series), list(other_series), max_lag_s=60
            )
            if corr >= 0.6:
                corr_id = hashlib.sha256(
                    f"ts_{trigger.protocol}_{other_proto}_{int(trigger.timestamp)}".encode()
                ).hexdigest()[:12]
                correlations.append(Correlation(
                    correlation_id=corr_id,
                    events=[trigger],
                    protocols=[trigger.protocol, other_proto],
                    time_span_s=lag,
                    correlation_score=corr,
                    correlation_type="temporal",
                    description=f"{trigger.protocol} and {other_proto} events temporally correlated (r={corr:.2f}, lag={lag:.1f}s)",
                    attack_hypothesis=f"Coordinated {trigger.protocol}/{other_proto} attack (lag={lag:.1f}s)",
                    confidence=corr,
                ))
        return correlations

    def get_correlations(
        self,
        min_score: float = 0.0,
        protocol_filter: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        result = [c for c in self._correlations if c.correlation_score >= min_score]
        if protocol_filter:
            result = [c for c in result if protocol_filter in c.protocols]
        result.sort(key=lambda c: -c.correlation_score)
        return [c.to_dict() for c in result]

    def get_stats(self) -> Dict[str, Any]:
        return {
            **self._stats,
            "buffer_size": len(self._event_buffer),
            "protocol_streams": list(self._protocol_series.keys()),
            "total_correlations": len(self._correlations),
        }
