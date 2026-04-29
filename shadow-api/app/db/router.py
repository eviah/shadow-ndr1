"""
Neural-Symbolic Query Router
─────────────────────────────
Picks the right datastore for a query based on its intent — not because
we have a neural model deciding (we don't, and we don't need one), but
because the symbolic rules below encode the actual cost characteristics
of Redis vs. Postgres vs. ClickHouse for an aviation NDR workload:

  Redis        — sub-ms key/value lookup, LIVE/HOT data only (≤ 5 min old)
  PostgreSQL   — relational forensics, joins, single-row by id, recent
                 alerts / threats / assets (≤ 30 days)
  ClickHouse   — wide-range analytics, aggregations over months of data,
                 timeseries roll-ups

Every public route should call `route_query()` instead of hitting one
backend directly. The router exposes Prometheus metrics so you can see
which intent is hitting which store, and a fallback chain when the
preferred store misses.
"""

from __future__ import annotations

import enum
import re
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional

from loguru import logger
from prometheus_client import Counter, Histogram


router_decisions = Counter(
    "query_router_decisions_total",
    "Routing decisions by intent and chosen backend",
    ["intent", "backend"],
)
router_latency = Histogram(
    "query_router_latency_seconds",
    "Total latency including routing overhead",
    ["intent", "backend"],
)
router_fallback = Counter(
    "query_router_fallback_total",
    "Times the primary backend missed and we fell through",
    ["intent", "from_backend", "to_backend"],
)


class Intent(str, enum.Enum):
    LIVE_STATUS = "live_status"          # current asset state, dashboard tiles
    RECENT_FORENSICS = "recent_forensics"  # last 24h-30d, by id, joined
    HISTORICAL_TRENDS = "historical_trends"  # months of data, aggregations
    SENSOR_HOT = "sensor_hot"            # last frame per icao24
    AUDIT_LOOKUP = "audit_lookup"        # exact row by primary key


class Backend(str, enum.Enum):
    REDIS = "redis"
    POSTGRES = "postgres"
    CLICKHOUSE = "clickhouse"


# ─── Symbolic intent classifier ───────────────────────────────────────────
#
# Pattern → (Intent, primary backend, fallback chain).
# Order matters; first match wins.

_RULES: List[tuple] = [
    # Live tiles — anything with "current", "latest", "now", "live"
    (re.compile(r"\b(current|latest|now|live|active)\b", re.I),
     Intent.LIVE_STATUS, Backend.REDIS, [Backend.POSTGRES]),

    # Sensor hot path — last position by icao24
    (re.compile(r"\b(last_frame|hot|position_by_icao|track_now)\b", re.I),
     Intent.SENSOR_HOT, Backend.REDIS, [Backend.POSTGRES]),

    # Historical / analytics — months / years / aggregations
    (re.compile(
        r"\b(GROUP\s+BY|COUNT|SUM|AVG|histogram|trend|month|year|"
        r"timeseries|rolling|last_\d{2,}_days)\b", re.I),
     Intent.HISTORICAL_TRENDS, Backend.CLICKHOUSE, [Backend.POSTGRES]),

    # Audit lookup — exact id
    (re.compile(r"\bWHERE\s+id\s*=\s*\$?\d+|\bid\s*=\s*['\"]?\w+", re.I),
     Intent.AUDIT_LOOKUP, Backend.POSTGRES, []),

    # Recent forensics — joins, where on tenant + recent timestamp
    (re.compile(r"\b(JOIN|tenant_id|severity|alert|threat|asset)\b", re.I),
     Intent.RECENT_FORENSICS, Backend.POSTGRES, [Backend.CLICKHOUSE]),
]


def classify(query_or_hint: str) -> tuple[Intent, Backend, List[Backend]]:
    """Return (intent, primary backend, fallback chain) for a query.
    The argument can be a raw SQL string OR a high-level hint like
    'live_status' / 'historical_trends' — caller's choice."""
    text = query_or_hint or ""
    # Direct intent string short-circuit
    for it in Intent:
        if it.value == text.lower():
            return _intent_default(it)
    for pattern, intent, primary, fallback in _RULES:
        if pattern.search(text):
            return intent, primary, list(fallback)
    return Intent.RECENT_FORENSICS, Backend.POSTGRES, [Backend.CLICKHOUSE]


def _intent_default(intent: Intent) -> tuple[Intent, Backend, List[Backend]]:
    return {
        Intent.LIVE_STATUS:        (intent, Backend.REDIS,      [Backend.POSTGRES]),
        Intent.SENSOR_HOT:         (intent, Backend.REDIS,      [Backend.POSTGRES]),
        Intent.HISTORICAL_TRENDS:  (intent, Backend.CLICKHOUSE, [Backend.POSTGRES]),
        Intent.AUDIT_LOOKUP:       (intent, Backend.POSTGRES,   []),
        Intent.RECENT_FORENSICS:   (intent, Backend.POSTGRES,   [Backend.CLICKHOUSE]),
    }[intent]


# ─── Result types ─────────────────────────────────────────────────────────

@dataclass
class RoutedResult:
    backend: Backend
    intent: Intent
    rows: Any
    elapsed_ms: float
    from_fallback: bool = False
    miss_chain: List[Backend] = field(default_factory=list)


# ─── Router itself ────────────────────────────────────────────────────────

class QueryRouter:
    """
    Wraps a Database instance and dispatches queries to the cheapest
    backend for the inferred intent, with a typed fallback chain when
    the primary returns no rows / errors.
    """

    def __init__(self, database):
        self.db = database

    async def route(self, *,
                    intent_or_query: str,
                    redis_key: Optional[str] = None,
                    pg_query: Optional[str] = None,
                    pg_args: tuple = (),
                    clickhouse_query: Optional[str] = None,
                    clickhouse_args: Optional[tuple] = None,
                    cache_ttl_s: int = 5) -> RoutedResult:
        """Dispatch a logical query.

        Provide *all* the implementations you have for this query
        (Redis key, Postgres SQL, ClickHouse SQL); the router calls only
        the one matching the inferred intent and falls back only if it
        misses or errors.
        """
        intent, primary, fallback = classify(intent_or_query)
        chain = [primary] + fallback
        miss_chain: List[Backend] = []

        for idx, backend in enumerate(chain):
            t0 = time.time()
            try:
                rows = await self._call(backend, redis_key=redis_key,
                                       pg_query=pg_query, pg_args=pg_args,
                                       clickhouse_query=clickhouse_query,
                                       clickhouse_args=clickhouse_args)
            except Exception as e:
                logger.debug(f"router: {backend.value} errored ({e}), trying fallback")
                miss_chain.append(backend)
                continue
            elapsed = (time.time() - t0) * 1000.0
            if rows is None or (isinstance(rows, list) and not rows):
                # Miss → fall through, but only if we have an alternative
                if idx < len(chain) - 1:
                    miss_chain.append(backend)
                    router_fallback.labels(intent=intent.value,
                                          from_backend=backend.value,
                                          to_backend=chain[idx + 1].value).inc()
                    continue

            # Optional write-through to Redis for live-intent results we
            # got from a slower store, so the next call short-circuits.
            if (intent in (Intent.LIVE_STATUS, Intent.SENSOR_HOT)
                    and backend != Backend.REDIS
                    and redis_key
                    and rows
                    and self.db.redis_client):
                try:
                    import json
                    await self.db.redis_client.setex(
                        redis_key, cache_ttl_s,
                        json.dumps(rows, default=str),
                    )
                except Exception:
                    pass

            router_decisions.labels(intent=intent.value, backend=backend.value).inc()
            router_latency.labels(intent=intent.value,
                                 backend=backend.value).observe(elapsed / 1000.0)
            return RoutedResult(
                backend=backend, intent=intent, rows=rows,
                elapsed_ms=elapsed,
                from_fallback=(backend != primary),
                miss_chain=miss_chain,
            )

        # Everything missed
        return RoutedResult(
            backend=primary, intent=intent, rows=[],
            elapsed_ms=0.0, from_fallback=True, miss_chain=miss_chain,
        )

    async def _call(self, backend: Backend, *, redis_key, pg_query,
                    pg_args, clickhouse_query, clickhouse_args):
        if backend == Backend.REDIS:
            if not redis_key or not self.db.redis_client:
                return None
            raw = await self.db.redis_client.get(redis_key)
            if raw is None:
                return None
            import json
            try:
                return json.loads(raw)
            except (TypeError, ValueError):
                return raw

        if backend == Backend.POSTGRES:
            if not pg_query:
                return None
            return await self.db.fetch(pg_query, *pg_args)

        if backend == Backend.CLICKHOUSE:
            if not clickhouse_query:
                return None
            return await self.db.clickhouse_execute(clickhouse_query,
                                                   clickhouse_args)
        return None
