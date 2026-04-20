"""
core/audit_log.py — structured JSON audit log.

Writes one JSON line per request to logs/audit.jsonl and to the logger.
Also emits a tripwire event to Kafka when a canary / blocked / forbidden
path is hit, if a threat consumer is available.
"""

from __future__ import annotations

import json
import logging
import os
import threading
import time
from pathlib import Path
from typing import Any, Dict, Optional

logger = logging.getLogger("shadow.audit")

_LOG_DIR = Path(os.environ.get("SHADOW_LOG_DIR", "logs"))
_LOG_FILE = _LOG_DIR / "audit.jsonl"
_WRITE_LOCK = threading.Lock()
_INITIALIZED = False


def _init() -> None:
    global _INITIALIZED
    if _INITIALIZED:
        return
    try:
        _LOG_DIR.mkdir(parents=True, exist_ok=True)
    except Exception as exc:
        logger.warning("Cannot create audit log dir %s: %s", _LOG_DIR, exc)
    _INITIALIZED = True


def record(event: Dict[str, Any]) -> None:
    """Append one structured event to the audit log (JSON line)."""
    _init()
    event.setdefault("ts", time.time())
    event.setdefault("level", "info")

    line = json.dumps(event, default=str, ensure_ascii=False)
    try:
        with _WRITE_LOCK:
            with _LOG_FILE.open("a", encoding="utf-8") as f:
                f.write(line + "\n")
    except Exception as exc:
        logger.warning("Audit log write failed: %s", exc)

    lvl = event.get("level", "info")
    if lvl in ("critical", "alert"):
        logger.critical("AUDIT %s", line)
    elif lvl in ("error", "warning"):
        logger.warning("AUDIT %s", line)
    else:
        logger.info("AUDIT %s", line)


def critical(message: str, **fields: Any) -> None:
    fields["level"] = "critical"
    fields["message"] = message
    record(fields)
    _emit_tripwire(fields)


def warn(message: str, **fields: Any) -> None:
    fields["level"] = "warning"
    fields["message"] = message
    record(fields)


def info(message: str, **fields: Any) -> None:
    fields["level"] = "info"
    fields["message"] = message
    record(fields)


def _emit_tripwire(event: Dict[str, Any]) -> None:
    """Best-effort: publish tripwire to Kafka shadow.threats; non-fatal."""
    try:
        from orchestrator.threat_consumer import get_threat_consumer  # noqa: F401
    except Exception:
        return
    try:
        from streaming.kafka_engine import get_kafka_engine  # type: ignore

        ke = get_kafka_engine()
        ke.publish(
            "shadow.threats",
            {
                "source": "shadow-ml.tripwire",
                "event_type": "canary_hit",
                "severity": "critical",
                "details": event,
            },
        )
    except Exception:
        # Kafka not running during local dev — fine.
        pass

    # Best-effort webhook
    url = os.environ.get("SHADOW_ALERT_WEBHOOK_URL", "").strip()
    if not url:
        return
    try:
        import httpx

        with httpx.Client(timeout=2.0) as client:
            client.post(url, json={"text": f"SHADOW-ML ALERT: {event.get('message')}", "event": event})
    except Exception:
        pass


def tail(n: int = 100) -> list[Dict[str, Any]]:
    """Return the last n audit events (for dashboards)."""
    _init()
    if not _LOG_FILE.exists():
        return []
    try:
        with _LOG_FILE.open("r", encoding="utf-8") as f:
            lines = f.readlines()[-n:]
        return [json.loads(line) for line in lines if line.strip()]
    except Exception as exc:
        logger.warning("Audit log tail failed: %s", exc)
        return []
