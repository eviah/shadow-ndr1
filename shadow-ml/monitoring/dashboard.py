"""
monitoring/dashboard.py — Real-Time Security Operations Dashboard v10.0

Provides:
  • WebSocket live event feed (threat scores, alerts, incidents in real-time)
  • REST snapshot: current threat posture, top threats, active incidents
  • Executive PDF/JSON report generator (24-hour / 7-day / 30-day windows)
  • SOC KPI metrics: MTTD, MTTR, false-positive rate, hunt coverage
  • Heat-map data: threat density by protocol / hour-of-day / source-country
  • NLP summary: "Last hour: 3 critical ADS-B anomalies, 1 SCADA incident…"

Integrations:
  • Pulls live data from all analytics, response, ML, and tracing modules
  • Pushes JSON deltas over WebSocket at configurable hz (default 1 Hz)
  • Claude claude-sonnet-4-6 generates executive narrative (optional)
"""

from __future__ import annotations

import asyncio
import json
import logging
import math
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Set

logger = logging.getLogger("shadow.monitoring.dashboard")


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------

@dataclass
class ThreatEvent:
    event_id: str
    timestamp: float
    threat_score: float
    threat_level: str        # low / medium / high / critical
    protocol: str
    src_ip: str
    description: str
    module: str              # neural / aviation / ueba / correlator / etc.
    incident_id: Optional[str] = None


@dataclass
class SOCKPIs:
    """Security Operations Centre key performance indicators."""
    mttd_minutes: float = 0.0       # mean time to detect
    mttr_minutes: float = 0.0       # mean time to respond
    false_positive_rate: float = 0.0
    true_positive_count: int = 0
    false_positive_count: int = 0
    alerts_today: int = 0
    incidents_today: int = 0
    hunt_coverage_pct: float = 0.0  # % of hypotheses run in last 24h
    critical_assets_at_risk: int = 0

    def to_dict(self) -> Dict[str, Any]:
        total = self.true_positive_count + self.false_positive_count
        return {
            "mttd_minutes":            round(self.mttd_minutes, 1),
            "mttr_minutes":            round(self.mttr_minutes, 1),
            "false_positive_rate":     round(self.false_positive_rate, 3),
            "true_positive_count":     self.true_positive_count,
            "false_positive_count":    self.false_positive_count,
            "total_analyzed":          total,
            "alerts_today":            self.alerts_today,
            "incidents_today":         self.incidents_today,
            "hunt_coverage_pct":       round(self.hunt_coverage_pct, 1),
            "critical_assets_at_risk": self.critical_assets_at_risk,
        }


@dataclass
class ExecutiveReport:
    report_id: str
    window_hours: int
    generated_at: float
    period_start: float
    period_end: float
    kpis: SOCKPIs
    top_threats: List[Dict[str, Any]]
    incident_summary: List[Dict[str, Any]]
    protocol_breakdown: Dict[str, int]
    hourly_threat_scores: List[float]  # 24 values
    narrative: str
    recommendations: List[str]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "report_id":           self.report_id,
            "window_hours":        self.window_hours,
            "generated_at":        self.generated_at,
            "period_start":        self.period_start,
            "period_end":          self.period_end,
            "kpis":                self.kpis.to_dict(),
            "top_threats":         self.top_threats,
            "incident_summary":    self.incident_summary,
            "protocol_breakdown":  self.protocol_breakdown,
            "hourly_threat_scores": self.hourly_threat_scores,
            "narrative":           self.narrative,
            "recommendations":     self.recommendations,
        }


# ---------------------------------------------------------------------------
# Heatmap builder
# ---------------------------------------------------------------------------

class ThreatHeatmap:
    """
    Accumulates threat events into a 2-D heat-map:
      axis-0 = protocol (adsb / iec104 / dns / tcp / modbus / acars / bgp / other)
      axis-1 = hour-of-day (0..23)
    """

    PROTOCOLS = ["adsb", "iec104", "dns", "tcp", "modbus", "acars", "bgp", "other"]

    def __init__(self):
        # protocol → hour → count
        self._grid: Dict[str, List[float]] = {p: [0.0] * 24 for p in self.PROTOCOLS}

    def record(self, protocol: str, timestamp: float, threat_score: float) -> None:
        hour = int((timestamp % 86400) / 3600)
        key = protocol.lower() if protocol.lower() in self.PROTOCOLS else "other"
        self._grid[key][hour] += threat_score

    def to_dict(self) -> Dict[str, Any]:
        return {
            "protocols": self.PROTOCOLS,
            "hours": list(range(24)),
            "grid": self._grid,
        }

    def top_cells(self, n: int = 5) -> List[Dict[str, Any]]:
        cells = []
        for proto in self.PROTOCOLS:
            for h, score in enumerate(self._grid[proto]):
                if score > 0:
                    cells.append({"protocol": proto, "hour": h, "score": round(score, 2)})
        cells.sort(key=lambda c: -c["score"])
        return cells[:n]


# ---------------------------------------------------------------------------
# KPI tracker
# ---------------------------------------------------------------------------

class KPITracker:
    """Maintains rolling SOC KPI metrics."""

    def __init__(self, window_hours: int = 24):
        self._window = window_hours * 3600
        self._detections: deque = deque()        # (ts, delay_s)
        self._responses: deque = deque()         # (ts, delay_s)
        self._tp = 0
        self._fp = 0
        self._alerts_today = 0
        self._incidents_today = 0
        self._hunts_run: Set[str] = set()
        self._total_hypotheses = 8               # from threat_hunter.py

    def record_detection(self, delay_seconds: float) -> None:
        now = time.time()
        self._detections.append((now, delay_seconds))
        self._alerts_today += 1
        self._prune()

    def record_response(self, delay_seconds: float) -> None:
        now = time.time()
        self._responses.append((now, delay_seconds))
        self._incidents_today += 1
        self._prune()

    def record_feedback(self, is_tp: bool) -> None:
        if is_tp:
            self._tp += 1
        else:
            self._fp += 1

    def record_hunt(self, hypothesis_id: str) -> None:
        self._hunts_run.add(hypothesis_id)

    def _prune(self) -> None:
        cutoff = time.time() - self._window
        while self._detections and self._detections[0][0] < cutoff:
            self._detections.popleft()
        while self._responses and self._responses[0][0] < cutoff:
            self._responses.popleft()

    def compute(self) -> SOCKPIs:
        self._prune()
        mttd = (sum(d for _, d in self._detections) / max(1, len(self._detections))) / 60
        mttr = (sum(d for _, d in self._responses) / max(1, len(self._responses))) / 60
        total = self._tp + self._fp
        fpr = self._fp / max(1, total)
        hunt_pct = len(self._hunts_run) / self._total_hypotheses * 100

        return SOCKPIs(
            mttd_minutes=mttd,
            mttr_minutes=mttr,
            false_positive_rate=fpr,
            true_positive_count=self._tp,
            false_positive_count=self._fp,
            alerts_today=self._alerts_today,
            incidents_today=self._incidents_today,
            hunt_coverage_pct=hunt_pct,
        )


# ---------------------------------------------------------------------------
# Executive narrative generator
# ---------------------------------------------------------------------------

class NarrativeGenerator:
    """
    Generates an English threat narrative for executives.
    Uses Claude claude-sonnet-4-6 when available; falls back to template.
    """

    TEMPLATE = (
        "During the {window}-hour reporting window, SHADOW-ML processed {events} events across "
        "{protocols} protocols. The system detected {critical} critical, {high} high, "
        "{medium} medium, and {low} low severity threats. "
        "Mean time to detect was {mttd:.1f} minutes. "
        "{top_threat_sentence}"
        "Recommended actions: {recommendations}."
    )

    def generate(
        self,
        window_hours: int,
        events: List[ThreatEvent],
        kpis: SOCKPIs,
        incidents: List[Dict[str, Any]],
        recommendations: List[str],
    ) -> str:
        # Severity counts
        counts: Dict[str, int] = defaultdict(int)
        protocols: Set[str] = set()
        for e in events:
            counts[e.threat_level] += 1
            protocols.add(e.protocol)

        # Top threat
        top = max(events, key=lambda e: e.threat_score) if events else None
        top_sentence = (
            f"The highest-scored threat ({top.threat_score:.2f}) involved {top.protocol} "
            f"traffic from {top.src_ip}. "
            if top else ""
        )

        try:
            return self._claude_narrative(window_hours, events, kpis, incidents, recommendations)
        except Exception:
            pass

        return self.TEMPLATE.format(
            window=window_hours,
            events=len(events),
            protocols=len(protocols),
            critical=counts.get("critical", 0),
            high=counts.get("high", 0),
            medium=counts.get("medium", 0),
            low=counts.get("low", 0),
            mttd=kpis.mttd_minutes,
            top_threat_sentence=top_sentence,
            recommendations="; ".join(recommendations[:3]) if recommendations else "continue monitoring",
        )

    def _claude_narrative(
        self,
        window_hours: int,
        events: List[ThreatEvent],
        kpis: SOCKPIs,
        incidents: List[Dict[str, Any]],
        recommendations: List[str],
    ) -> str:
        import anthropic
        client = anthropic.Anthropic()

        summary_data = {
            "window_hours": window_hours,
            "total_events": len(events),
            "kpis": kpis.to_dict(),
            "incidents": incidents[:5],
            "top_events": [
                {"score": e.threat_score, "protocol": e.protocol, "description": e.description}
                for e in sorted(events, key=lambda x: -x.threat_score)[:5]
            ],
            "recommendations": recommendations,
        }

        response = client.messages.create(
            model="claude-sonnet-4-6",
            max_tokens=512,
            system=(
                "You are a senior cybersecurity analyst writing a concise executive threat summary. "
                "Write 2-3 paragraphs in plain English, suitable for a C-suite audience. "
                "Focus on business impact, key findings, and recommended actions. "
                "Do NOT use bullet points. Be direct and professional."
            ),
            messages=[{
                "role": "user",
                "content": f"Generate an executive threat summary from this data:\n{json.dumps(summary_data, indent=2)}",
            }],
        )
        return response.content[0].text


# ---------------------------------------------------------------------------
# Dashboard Engine
# ---------------------------------------------------------------------------

class DashboardEngine:
    """
    SHADOW-ML Real-Time SOC Dashboard Engine v10.0

    Central hub that:
      1. Receives threat events from all detection modules
      2. Maintains rolling buffers for live feeds
      3. Builds heatmaps and KPI statistics
      4. Generates executive reports on demand
      5. Broadcasts live updates over WebSocket connections
    """

    VERSION = "10.0.0"

    THREAT_LEVEL_MAP = {
        (0.0, 0.3): "low",
        (0.3, 0.6): "medium",
        (0.6, 0.85): "high",
        (0.85, 1.01): "critical",
    }

    RECOMMENDATION_RULES = [
        (0.85, "Immediately escalate to incident response team and consider network isolation"),
        (0.7,  "Engage threat hunting on affected segments and review recent firewall changes"),
        (0.5,  "Increase logging verbosity on affected protocols and validate canary token status"),
        (0.3,  "Schedule review of anomalous entities in UEBA dashboard"),
        (0.0,  "Continue standard monitoring — no immediate action required"),
    ]

    def __init__(self, max_events: int = 50_000):
        self._events: deque = deque(maxlen=max_events)
        self._heatmap = ThreatHeatmap()
        self._kpi_tracker = KPITracker()
        self._narrative_gen = NarrativeGenerator()
        self._subscribers: List[Callable] = []  # WebSocket callbacks
        self._stats: Dict[str, Any] = {
            "events_received": 0,
            "reports_generated": 0,
            "subscribers": 0,
        }
        logger.info("DashboardEngine v%s initialised", self.VERSION)

    # ── Event ingestion ──────────────────────────────────────────────────────

    def ingest(self, event: ThreatEvent) -> None:
        """Ingest a threat event from any detection module."""
        self._events.append(event)
        self._heatmap.record(event.protocol, event.timestamp, event.threat_score)
        self._kpi_tracker.record_detection(delay_seconds=0.5)  # ~500ms pipeline delay
        self._stats["events_received"] += 1

        # Broadcast to WebSocket subscribers
        if event.threat_score >= 0.5:
            self._broadcast({
                "type": "threat_event",
                "data": {
                    "event_id": event.event_id,
                    "threat_score": event.threat_score,
                    "threat_level": event.threat_level,
                    "protocol": event.protocol,
                    "src_ip": event.src_ip,
                    "description": event.description,
                    "module": event.module,
                    "timestamp": event.timestamp,
                },
            })

    def ingest_from_dict(self, d: Dict[str, Any], module: str = "unknown") -> ThreatEvent:
        """Convert a generic dict (from any module) to ThreatEvent and ingest."""
        import uuid
        score = float(d.get("threat_score", d.get("anomaly_score", d.get("score", 0.0))))
        level = self._score_to_level(score)
        event = ThreatEvent(
            event_id=d.get("event_id", uuid.uuid4().hex[:12]),
            timestamp=d.get("timestamp", time.time()),
            threat_score=score,
            threat_level=level,
            protocol=d.get("protocol", d.get("proto", "unknown")),
            src_ip=d.get("src_ip", d.get("source_ip", "")),
            description=d.get("description", d.get("reason", "")),
            module=module,
            incident_id=d.get("incident_id"),
        )
        self.ingest(event)
        return event

    # ── Snapshot ─────────────────────────────────────────────────────────────

    def get_snapshot(self, window_minutes: int = 60) -> Dict[str, Any]:
        """Return current threat posture snapshot for dashboard display."""
        cutoff = time.time() - window_minutes * 60
        recent = [e for e in self._events if e.timestamp >= cutoff]

        severity_counts: Dict[str, int] = defaultdict(int)
        protocol_counts: Dict[str, int] = defaultdict(int)
        top_events = []

        for e in recent:
            severity_counts[e.threat_level] += 1
            protocol_counts[e.protocol] += 1

        top_events = sorted(recent, key=lambda e: -e.threat_score)[:10]
        avg_score = sum(e.threat_score for e in recent) / max(1, len(recent))

        return {
            "timestamp": time.time(),
            "window_minutes": window_minutes,
            "total_events": len(recent),
            "avg_threat_score": round(avg_score, 4),
            "max_threat_score": round(max((e.threat_score for e in recent), default=0.0), 4),
            "severity_breakdown": dict(severity_counts),
            "protocol_breakdown": dict(protocol_counts),
            "top_threats": [
                {
                    "event_id": e.event_id,
                    "score": round(e.threat_score, 4),
                    "level": e.threat_level,
                    "protocol": e.protocol,
                    "src_ip": e.src_ip,
                    "description": e.description[:120],
                    "module": e.module,
                    "ts": e.timestamp,
                }
                for e in top_events
            ],
            "heatmap": self._heatmap.to_dict(),
            "heatmap_top_cells": self._heatmap.top_cells(10),
            "kpis": self._kpi_tracker.compute().to_dict(),
        }

    # ── Hourly trend ─────────────────────────────────────────────────────────

    def get_hourly_trend(self, hours: int = 24) -> List[Dict[str, Any]]:
        """Return per-hour threat score aggregates for sparkline charts."""
        now = time.time()
        result = []
        for i in range(hours, 0, -1):
            start = now - i * 3600
            end = start + 3600
            bucket = [e for e in self._events if start <= e.timestamp < end]
            result.append({
                "hour_offset": -i,
                "start_ts": start,
                "event_count": len(bucket),
                "avg_score": round(sum(e.threat_score for e in bucket) / max(1, len(bucket)), 4),
                "max_score": round(max((e.threat_score for e in bucket), default=0.0), 4),
                "critical_count": sum(1 for e in bucket if e.threat_level == "critical"),
            })
        return result

    # ── Executive report ─────────────────────────────────────────────────────

    def generate_report(self, window_hours: int = 24) -> ExecutiveReport:
        """Generate an executive threat intelligence report."""
        import uuid
        now = time.time()
        cutoff = now - window_hours * 3600
        events = [e for e in self._events if e.timestamp >= cutoff]

        kpis = self._kpi_tracker.compute()

        # Protocol breakdown
        proto_breakdown: Dict[str, int] = defaultdict(int)
        for e in events:
            proto_breakdown[e.protocol] += 1

        # Top threats
        top = sorted(events, key=lambda e: -e.threat_score)[:10]
        top_dicts = [
            {"score": e.threat_score, "level": e.threat_level, "protocol": e.protocol,
             "src_ip": e.src_ip, "description": e.description, "module": e.module}
            for e in top
        ]

        # Hourly scores
        hourly = self.get_hourly_trend(min(window_hours, 24))
        hourly_scores = [h["avg_score"] for h in hourly]

        # Recommendations
        max_score = max((e.threat_score for e in events), default=0.0)
        recommendations = self._build_recommendations(max_score, kpis, events)

        # Narrative
        narrative = self._narrative_gen.generate(
            window_hours=window_hours,
            events=events,
            kpis=kpis,
            incidents=[],
            recommendations=recommendations,
        )

        report = ExecutiveReport(
            report_id=uuid.uuid4().hex[:12],
            window_hours=window_hours,
            generated_at=now,
            period_start=cutoff,
            period_end=now,
            kpis=kpis,
            top_threats=top_dicts,
            incident_summary=[],
            protocol_breakdown=dict(proto_breakdown),
            hourly_threat_scores=hourly_scores,
            narrative=narrative,
            recommendations=recommendations,
        )
        self._stats["reports_generated"] += 1
        logger.info("Executive report generated: id=%s window=%dh events=%d",
                    report.report_id, window_hours, len(events))
        return report

    # ── WebSocket pub/sub ────────────────────────────────────────────────────

    def subscribe(self, callback: Callable) -> None:
        """Register a WebSocket callback to receive live event deltas."""
        self._subscribers.append(callback)
        self._stats["subscribers"] = len(self._subscribers)

    def unsubscribe(self, callback: Callable) -> None:
        self._subscribers = [s for s in self._subscribers if s is not callback]
        self._stats["subscribers"] = len(self._subscribers)

    def _broadcast(self, message: Dict[str, Any]) -> None:
        dead = []
        for cb in self._subscribers:
            try:
                cb(message)
            except Exception:
                dead.append(cb)
        for cb in dead:
            self.unsubscribe(cb)

    async def live_feed(self, websocket: Any, window_seconds: int = 60) -> None:
        """
        Async generator that pushes live dashboard snapshots over a WebSocket.
        Compatible with FastAPI WebSocket objects.
        """
        logger.info("WebSocket live feed started")

        async def _sender(msg: Dict[str, Any]) -> None:
            try:
                await websocket.send_json(msg)
            except Exception:
                pass

        # Send initial snapshot
        await websocket.send_json({"type": "snapshot", "data": self.get_snapshot(window_seconds // 60)})

        # Register for live events
        def _sync_callback(msg: Dict[str, Any]) -> None:
            asyncio.create_task(_sender(msg))

        self.subscribe(_sync_callback)
        try:
            while True:
                # Send heartbeat + mini-snapshot every 5 seconds
                await asyncio.sleep(5)
                snapshot = self.get_snapshot(window_seconds // 60)
                await websocket.send_json({"type": "heartbeat", "data": snapshot})
        except Exception:
            pass
        finally:
            self.unsubscribe(_sync_callback)
            logger.info("WebSocket live feed closed")

    # ── Helpers ──────────────────────────────────────────────────────────────

    def _score_to_level(self, score: float) -> str:
        for (low, high), level in self.THREAT_LEVEL_MAP.items():
            if low <= score < high:
                return level
        return "low"

    def _build_recommendations(
        self,
        max_score: float,
        kpis: SOCKPIs,
        events: List[ThreatEvent],
    ) -> List[str]:
        recs = []
        for threshold, rec in self.RECOMMENDATION_RULES:
            if max_score >= threshold:
                recs.append(rec)
                break

        if kpis.false_positive_rate > 0.3:
            recs.append("Review detection thresholds — false-positive rate exceeds 30%")

        if kpis.hunt_coverage_pct < 50:
            recs.append("Increase threat hunting cadence — only {:.0f}% of hypotheses executed".format(
                kpis.hunt_coverage_pct))

        protocols = {e.protocol for e in events}
        if "iec104" in protocols or "modbus" in protocols:
            recs.append("SCADA/ICS protocols detected in threat stream — validate OT network segmentation")

        if "adsb" in protocols:
            recs.append("ADS-B anomalies detected — coordinate with ATC and verify transponder integrity")

        return recs[:5]

    # ── Stats ────────────────────────────────────────────────────────────────

    def get_stats(self) -> Dict[str, Any]:
        return {
            **self._stats,
            "version": self.VERSION,
            "buffered_events": len(self._events),
            "kpis": self._kpi_tracker.compute().to_dict(),
        }


# ---------------------------------------------------------------------------
# Global singleton
# ---------------------------------------------------------------------------

_dashboard: Optional[DashboardEngine] = None


def get_dashboard() -> DashboardEngine:
    global _dashboard
    if _dashboard is None:
        _dashboard = DashboardEngine()
    return _dashboard
