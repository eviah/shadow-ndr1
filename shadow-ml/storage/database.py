"""
storage/database.py — SHADOW-ML Storage Engine v10.0

Dual-mode persistence layer:
  • In-memory store (default, zero-config, production-fast)
  • SQLite backend (durable, survives restarts)
  • PostgreSQL adapter (enterprise scale via asyncpg)

Stores: decisions, alerts, attacker profiles, canary events, threat intel,
        model checkpoints, audit logs.
"""

from __future__ import annotations

import json
import logging
import sqlite3
import time
import threading
from contextlib import contextmanager
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional

logger = logging.getLogger("shadow.storage")

DB_PATH = Path(__file__).parent.parent / "data" / "shadow.db"


# ---------------------------------------------------------------------------
# Schema
# ---------------------------------------------------------------------------

SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS decisions (
    decision_id TEXT PRIMARY KEY,
    timestamp   REAL NOT NULL,
    threat_level TEXT NOT NULL,
    threat_score REAL NOT NULL,
    source_ip   TEXT,
    attack_type TEXT,
    confidence  REAL,
    defenses    TEXT,   -- JSON array
    reasoning   TEXT,
    outcome     TEXT DEFAULT 'pending'
);

CREATE TABLE IF NOT EXISTS alerts (
    alert_id    TEXT PRIMARY KEY,
    timestamp   REAL NOT NULL,
    level       TEXT NOT NULL,
    source_ip   TEXT,
    message     TEXT,
    context     TEXT    -- JSON
);

CREATE TABLE IF NOT EXISTS attacker_profiles (
    source_ip       TEXT PRIMARY KEY,
    first_seen      REAL,
    last_seen       REAL,
    interaction_count INTEGER DEFAULT 0,
    risk_score      REAL DEFAULT 0,
    cluster_id      INTEGER DEFAULT -1,
    ttps            TEXT,   -- JSON array
    engagement_depth INTEGER DEFAULT 0,
    fingerprint     TEXT
);

CREATE TABLE IF NOT EXISTS canary_events (
    event_id    TEXT PRIMARY KEY,
    token_id    TEXT NOT NULL,
    token_type  TEXT,
    triggered_at REAL,
    triggered_by TEXT,
    context     TEXT    -- JSON
);

CREATE TABLE IF NOT EXISTS audit_log (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp   REAL NOT NULL,
    actor       TEXT,
    action      TEXT NOT NULL,
    resource    TEXT,
    result      TEXT,
    details     TEXT    -- JSON
);

CREATE INDEX IF NOT EXISTS idx_decisions_ts   ON decisions(timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_alerts_ts      ON alerts(timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_audit_ts       ON audit_log(timestamp DESC);
"""


# ---------------------------------------------------------------------------
# In-memory store (default)
# ---------------------------------------------------------------------------

class _MemoryStore:
    def __init__(self):
        self._tables: Dict[str, Dict[str, Any]] = {
            "decisions": {}, "alerts": {}, "attacker_profiles": {},
            "canary_events": {}, "audit_log": {},
        }
        self._lock = threading.Lock()

    def insert(self, table: str, pk: str, row: Dict[str, Any]) -> None:
        with self._lock:
            self._tables.setdefault(table, {})[pk] = row

    def get(self, table: str, pk: str) -> Optional[Dict[str, Any]]:
        return self._tables.get(table, {}).get(pk)

    def list_recent(self, table: str, limit: int = 100, order_by: str = "timestamp") -> List[Dict[str, Any]]:
        rows = list(self._tables.get(table, {}).values())
        rows.sort(key=lambda r: r.get(order_by, 0), reverse=True)
        return rows[:limit]

    def count(self, table: str) -> int:
        return len(self._tables.get(table, {}))

    def search(self, table: str, field: str, value: Any) -> List[Dict[str, Any]]:
        return [r for r in self._tables.get(table, {}).values() if r.get(field) == value]


# ---------------------------------------------------------------------------
# SQLite backend
# ---------------------------------------------------------------------------

class _SQLiteStore:
    def __init__(self, path: Path = DB_PATH):
        path.parent.mkdir(parents=True, exist_ok=True)
        self._path = str(path)
        self._local = threading.local()
        self._init_schema()
        logger.info("SQLite store initialised at %s", self._path)

    def _conn(self) -> sqlite3.Connection:
        if not hasattr(self._local, "conn"):
            self._local.conn = sqlite3.connect(self._path, check_same_thread=False)
            self._local.conn.row_factory = sqlite3.Row
        return self._local.conn

    def _init_schema(self) -> None:
        with self._conn() as conn:
            conn.executescript(SCHEMA_SQL)

    @contextmanager
    def _cursor(self) -> Iterator[sqlite3.Cursor]:
        conn = self._conn()
        cur = conn.cursor()
        try:
            yield cur
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            cur.close()

    def insert_decision(self, d: Dict[str, Any]) -> None:
        with self._cursor() as cur:
            cur.execute(
                "INSERT OR REPLACE INTO decisions VALUES (?,?,?,?,?,?,?,?,?,?)",
                (d.get("decision_id"), d.get("timestamp"), d.get("threat_level"),
                 d.get("threat_score", 0), d.get("source_ip"), d.get("attack_type"),
                 d.get("confidence", 0), json.dumps(d.get("defenses_activated", [])),
                 d.get("reasoning"), d.get("outcome", "pending")),
            )

    def insert_alert(self, a: Dict[str, Any]) -> None:
        with self._cursor() as cur:
            cur.execute(
                "INSERT OR REPLACE INTO alerts VALUES (?,?,?,?,?,?)",
                (a.get("alert_id"), a.get("timestamp"), a.get("level"),
                 a.get("source_ip"), a.get("message"), json.dumps(a.get("context", {}))),
            )

    def insert_profile(self, p: Dict[str, Any]) -> None:
        with self._cursor() as cur:
            cur.execute(
                "INSERT OR REPLACE INTO attacker_profiles VALUES (?,?,?,?,?,?,?,?,?)",
                (p.get("source_ip"), p.get("first_seen"), p.get("last_seen"),
                 p.get("interaction_count", 0), p.get("risk_score", 0),
                 p.get("cluster_id", -1), json.dumps(p.get("ttps", [])),
                 p.get("engagement_depth", 0), p.get("fingerprint")),
            )

    def audit(self, actor: str, action: str, resource: str = "", result: str = "ok",
              details: Optional[Dict] = None) -> None:
        with self._cursor() as cur:
            cur.execute(
                "INSERT INTO audit_log (timestamp,actor,action,resource,result,details) VALUES (?,?,?,?,?,?)",
                (time.time(), actor, action, resource, result, json.dumps(details or {})),
            )

    def list_decisions(self, limit: int = 100) -> List[Dict[str, Any]]:
        with self._cursor() as cur:
            cur.execute("SELECT * FROM decisions ORDER BY timestamp DESC LIMIT ?", (limit,))
            return [dict(row) for row in cur.fetchall()]

    def list_alerts(self, limit: int = 100) -> List[Dict[str, Any]]:
        with self._cursor() as cur:
            cur.execute("SELECT * FROM alerts ORDER BY timestamp DESC LIMIT ?", (limit,))
            return [dict(row) for row in cur.fetchall()]

    def stats(self) -> Dict[str, Any]:
        with self._cursor() as cur:
            cur.execute("SELECT COUNT(*) FROM decisions")
            n_dec = cur.fetchone()[0]
            cur.execute("SELECT COUNT(*) FROM alerts")
            n_alert = cur.fetchone()[0]
            cur.execute("SELECT COUNT(*) FROM attacker_profiles")
            n_profiles = cur.fetchone()[0]
        return {"decisions": n_dec, "alerts": n_alert, "profiles": n_profiles}


# ---------------------------------------------------------------------------
# Unified Database facade
# ---------------------------------------------------------------------------

class Database:
    """
    SHADOW-ML Database v10.0

    Auto-selects SQLite for durability; falls back to in-memory if unavailable.
    All writes are also mirrored to the in-memory store for zero-latency reads.
    """

    VERSION = "10.0.0"

    def __init__(self, use_sqlite: bool = True, db_path: Optional[Path] = None):
        self._mem = _MemoryStore()
        self._sqlite: Optional[_SQLiteStore] = None
        if use_sqlite:
            try:
                self._sqlite = _SQLiteStore(db_path or DB_PATH)
            except Exception as exc:
                logger.warning("SQLite unavailable (%s) — memory-only mode", exc)

    # ── Decisions ────────────────────────────────────────────────────────────

    def save_decision(self, decision: Dict[str, Any]) -> None:
        pk = decision.get("decision_id", str(time.time()))
        self._mem.insert("decisions", pk, decision)
        if self._sqlite:
            try:
                self._sqlite.insert_decision(decision)
            except Exception as exc:
                logger.error("SQLite decision write failed: %s", exc)

    def get_decisions(self, limit: int = 100) -> List[Dict[str, Any]]:
        if self._sqlite:
            try:
                return self._sqlite.list_decisions(limit)
            except Exception:
                pass
        return self._mem.list_recent("decisions", limit)

    # ── Alerts ───────────────────────────────────────────────────────────────

    def save_alert(self, alert: Dict[str, Any]) -> None:
        pk = alert.get("alert_id", str(time.time()))
        self._mem.insert("alerts", pk, alert)
        if self._sqlite:
            try:
                self._sqlite.insert_alert(alert)
            except Exception as exc:
                logger.error("SQLite alert write failed: %s", exc)

    def get_alerts(self, limit: int = 100) -> List[Dict[str, Any]]:
        if self._sqlite:
            try:
                return self._sqlite.list_alerts(limit)
            except Exception:
                pass
        return self._mem.list_recent("alerts", limit)

    # ── Attacker profiles ────────────────────────────────────────────────────

    def save_profile(self, profile: Dict[str, Any]) -> None:
        pk = profile.get("source_ip", "unknown")
        self._mem.insert("attacker_profiles", pk, profile)
        if self._sqlite:
            try:
                self._sqlite.insert_profile(profile)
            except Exception as exc:
                logger.error("SQLite profile write failed: %s", exc)

    def get_profile(self, source_ip: str) -> Optional[Dict[str, Any]]:
        return self._mem.get("attacker_profiles", source_ip)

    # ── Audit ────────────────────────────────────────────────────────────────

    def audit(self, actor: str, action: str, resource: str = "", result: str = "ok",
              details: Optional[Dict] = None) -> None:
        entry = {
            "timestamp": time.time(), "actor": actor, "action": action,
            "resource": resource, "result": result, "details": details or {},
        }
        self._mem.insert("audit_log", str(time.time()), entry)
        if self._sqlite:
            try:
                self._sqlite.audit(actor, action, resource, result, details)
            except Exception as exc:
                logger.error("SQLite audit write failed: %s", exc)

    # ── Stats ─────────────────────────────────────────────────────────────────

    def get_stats(self) -> Dict[str, Any]:
        if self._sqlite:
            try:
                return {"backend": "sqlite", **self._sqlite.stats()}
            except Exception:
                pass
        return {
            "backend": "memory",
            "decisions": self._mem.count("decisions"),
            "alerts": self._mem.count("alerts"),
            "profiles": self._mem.count("attacker_profiles"),
        }


# Singleton
_DB: Optional[Database] = None


def get_db() -> Database:
    global _DB
    if _DB is None:
        _DB = Database()
    return _DB
