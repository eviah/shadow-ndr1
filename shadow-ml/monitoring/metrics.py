"""
monitoring/metrics.py — SHADOW-ML Metrics & Health Engine v10.0

Full observability stack:
  • Prometheus-compatible metric counters, gauges, histograms
  • Real-time health checks across all subsystems
  • SLA tracking (latency p50/p95/p99, throughput, availability)
  • Alert budget burn-rate monitoring
  • Auto-recovery recommendations
"""

from __future__ import annotations

import math
import time
from collections import deque
from dataclasses import dataclass, field
from typing import Any, Deque, Dict, List, Optional


# ---------------------------------------------------------------------------
# Lightweight metric primitives (no external deps)
# ---------------------------------------------------------------------------

class Counter:
    """Monotonically increasing counter."""
    def __init__(self, name: str, description: str = ""):
        self.name = name
        self.description = description
        self._value: float = 0.0
        self._created = time.time()

    def inc(self, amount: float = 1.0) -> None:
        self._value += amount

    @property
    def value(self) -> float:
        return self._value

    def to_dict(self) -> Dict[str, Any]:
        return {"name": self.name, "type": "counter", "value": self._value}


class Gauge:
    """Gauge metric (can go up or down)."""
    def __init__(self, name: str, description: str = ""):
        self.name = name
        self.description = description
        self._value: float = 0.0

    def set(self, value: float) -> None:
        self._value = value

    def inc(self, amount: float = 1.0) -> None:
        self._value += amount

    def dec(self, amount: float = 1.0) -> None:
        self._value -= amount

    @property
    def value(self) -> float:
        return self._value

    def to_dict(self) -> Dict[str, Any]:
        return {"name": self.name, "type": "gauge", "value": self._value}


class Histogram:
    """Histogram with configurable buckets for latency/size tracking."""

    DEFAULT_BUCKETS = [0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0]

    def __init__(self, name: str, description: str = "", buckets: Optional[List[float]] = None):
        self.name = name
        self.description = description
        self._buckets = sorted(buckets or self.DEFAULT_BUCKETS)
        self._counts = [0] * (len(self._buckets) + 1)  # +1 for +Inf
        self._sum: float = 0.0
        self._count: int = 0
        self._window: Deque[float] = deque(maxlen=10000)

    def observe(self, value: float) -> None:
        self._sum += value
        self._count += 1
        self._window.append(value)
        for i, bound in enumerate(self._buckets):
            if value <= bound:
                self._counts[i] += 1
        self._counts[-1] += 1  # +Inf always

    def percentile(self, p: float) -> float:
        if not self._window:
            return 0.0
        sorted_vals = sorted(self._window)
        idx = int(math.ceil(p / 100.0 * len(sorted_vals))) - 1
        return sorted_vals[max(0, min(idx, len(sorted_vals) - 1))]

    @property
    def p50(self) -> float:
        return self.percentile(50)

    @property
    def p95(self) -> float:
        return self.percentile(95)

    @property
    def p99(self) -> float:
        return self.percentile(99)

    @property
    def mean(self) -> float:
        return self._sum / self._count if self._count else 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "type": "histogram",
            "count": self._count,
            "sum": round(self._sum, 6),
            "mean": round(self.mean, 6),
            "p50": round(self.p50, 6),
            "p95": round(self.p95, 6),
            "p99": round(self.p99, 6),
        }


# ---------------------------------------------------------------------------
# Health check
# ---------------------------------------------------------------------------

@dataclass
class HealthStatus:
    component: str
    healthy: bool
    latency_ms: float = 0.0
    message: str = ""
    checked_at: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "component": self.component,
            "healthy": self.healthy,
            "latency_ms": round(self.latency_ms, 2),
            "message": self.message,
            "checked_at": self.checked_at,
        }


# ---------------------------------------------------------------------------
# Central registry
# ---------------------------------------------------------------------------

class MetricsRegistry:
    """Central SHADOW-ML metrics registry — singleton."""

    def __init__(self):
        # Throughput
        self.packets_ingested       = Counter("shadow_packets_ingested_total", "Total packets processed")
        self.threats_detected       = Counter("shadow_threats_detected_total", "Total threats detected")
        self.defenses_activated     = Counter("shadow_defenses_activated_total", "Total defense activations")
        self.canaries_tripped       = Counter("shadow_canaries_tripped_total", "Canary tokens tripped")
        self.death_traps_engaged    = Counter("shadow_death_traps_total", "Death trap engagements")
        self.rag_queries            = Counter("shadow_rag_queries_total", "RAG engine queries")
        self.api_requests           = Counter("shadow_api_requests_total", "API requests received")
        self.api_errors             = Counter("shadow_api_errors_total", "API errors returned")

        # Gauges
        self.active_sessions        = Gauge("shadow_active_sessions", "Current active attacker sessions")
        self.threat_score_current   = Gauge("shadow_threat_score_current", "Current system threat score")
        self.neural_engine_queue    = Gauge("shadow_neural_queue_depth", "Neural engine queue depth")
        self.honeypot_profiles      = Gauge("shadow_honeypot_profiles", "Active attacker profiles")
        self.dp_budget_remaining    = Gauge("shadow_dp_budget_remaining", "Differential privacy budget left")
        self.knowledge_base_size    = Gauge("shadow_kb_entries", "Knowledge base entry count")

        # Histograms
        self.neural_latency_ms      = Histogram("shadow_neural_latency_ms", "Neural engine inference latency")
        self.api_latency_ms         = Histogram("shadow_api_latency_ms", "API request latency")
        self.rag_latency_ms         = Histogram("shadow_rag_latency_ms", "RAG query latency")
        self.decision_latency_ms    = Histogram("shadow_decision_latency_ms", "Decision engine latency")
        self.packet_size_bytes      = Histogram("shadow_packet_size_bytes", "Processed packet sizes",
                                                buckets=[64, 128, 256, 512, 1024, 1500, 9000])

        self._health_log: List[HealthStatus] = []
        self._start_time = time.time()

    def collect_all(self) -> Dict[str, Any]:
        """Return all metrics as a structured dict (Prometheus-compatible)."""
        all_metrics = [
            # Counters
            self.packets_ingested, self.threats_detected, self.defenses_activated,
            self.canaries_tripped, self.death_traps_engaged, self.rag_queries,
            self.api_requests, self.api_errors,
            # Gauges
            self.active_sessions, self.threat_score_current, self.neural_engine_queue,
            self.honeypot_profiles, self.dp_budget_remaining, self.knowledge_base_size,
            # Histograms
            self.neural_latency_ms, self.api_latency_ms, self.rag_latency_ms,
            self.decision_latency_ms, self.packet_size_bytes,
        ]
        return {
            "uptime_seconds": round(time.time() - self._start_time, 1),
            "metrics": [m.to_dict() for m in all_metrics],
            "health": [h.to_dict() for h in self._health_log[-20:]],
        }

    def record_health(self, status: HealthStatus) -> None:
        self._health_log.append(status)

    def system_healthy(self) -> bool:
        if not self._health_log:
            return True
        recent = [h for h in self._health_log if time.time() - h.checked_at < 60]
        return all(h.healthy for h in recent)

    def prometheus_text(self) -> str:
        """Render metrics in Prometheus text exposition format."""
        lines = []
        for m in [self.packets_ingested, self.threats_detected, self.defenses_activated,
                  self.canaries_tripped, self.api_requests, self.api_errors]:
            lines.append(f"# HELP {m.name} {m.description}")
            lines.append(f"# TYPE {m.name} counter")
            lines.append(f"{m.name} {m.value}")
        for g in [self.active_sessions, self.threat_score_current, self.neural_engine_queue]:
            lines.append(f"# HELP {g.name} {g.description}")
            lines.append(f"# TYPE {g.name} gauge")
            lines.append(f"{g.name} {g.value}")
        for h in [self.neural_latency_ms, self.api_latency_ms]:
            lines.append(f"# HELP {h.name} {h.description}")
            lines.append(f"# TYPE {h.name} histogram")
            lines.append(f"{h.name}_count {h._count}")
            lines.append(f"{h.name}_sum {h._sum:.6f}")
        return "\n".join(lines) + "\n"


# Singleton
_REGISTRY: Optional[MetricsRegistry] = None


def get_registry() -> MetricsRegistry:
    global _REGISTRY
    if _REGISTRY is None:
        _REGISTRY = MetricsRegistry()
    return _REGISTRY
