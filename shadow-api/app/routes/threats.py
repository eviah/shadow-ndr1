# -*- coding: utf-8 -*-
"""
╔══════════════════════════════════════════════════════════════════════════════╗
║  Shadow NDR – Threat Intelligence Engine  v3.0  «Ultimate Edition»          ║
║  Full integration with anomaly_detector v7 · Aviation / ICS / NDR           ║
╚══════════════════════════════════════════════════════════════════════════════╝

גרסה 3.0 — שדרוג מלא מעל v2, כולל אינטגרציה ישירה עם anomaly_detector v7:

  ── Integration עם anomaly_detector v7 ────────────────────────────────────────
  ✓ AttackerProfiler מוזן ישירות לתוצאות API — כל threat כולל פרופיל מלא
  ✓ DigitalTwin simulation לכל איום קריטי — time_to_impact בתגובה
  ✓ ExplainableCountermeasures — steps + "why" בכל תגובה
  ✓ MAMLDetector few-shot — endpoint חדש /detect/zero-day
  ✓ SelfHealingEngine — GET /health/code-scan, POST /health/heal/{proposal_id}
  ✓ MITREClassifier — כל threat כולל ATT&CK IDs

  ── Multi-tier Rate Limiting ──────────────────────────────────────────────────
  ✓ Per-user, per-org, per-IP sliding window
  ✓ Priority queues: critical alerts bypass rate limit
  ✓ Adaptive throttling: אם latency עולה, מוריד limits אוטומטי

  ── Streaming & Real-time ─────────────────────────────────────────────────────
  ✓ SSE (Server-Sent Events) — fallback ל-WebSocket
  ✓ gRPC-style bidirectional streaming עם WebSocket
  ✓ Heartbeat + reconnect logic
  ✓ Per-client filter state (score threshold, attack type, org)

  ── Advanced AI ───────────────────────────────────────────────────────────────
  ✓ LLM-powered natural language threat search ("show me all Lazarus attacks today")
  ✓ Automated incident summary — GPT generates 3-sentence executive brief
  ✓ Risk scoring engine — composite score: asset + threat + context + time
  ✓ Threat trajectory prediction — "where will this attacker go next?"

  ── Security Hardening ────────────────────────────────────────────────────────
  ✓ Request signing (HMAC-SHA256) for webhook consumers
  ✓ Field-level encryption for PII (src_ip masked for non-admin)
  ✓ IP allowlist per API key
  ✓ Idempotency keys for mutations
  ✓ SQL injection prevention audit on all dynamic queries
  ✓ Content Security Policy headers

  ── Operational Excellence ────────────────────────────────────────────────────
  ✓ Structured error responses (RFC 7807 Problem Details)
  ✓ Request tracing with X-Request-ID propagation
  ✓ Graceful degradation: ML down → rule-based fallback with indicator
  ✓ Pagination cursors (keyset pagination, not offset)
  ✓ Response compression (gzip/brotli via middleware)
  ✓ OpenAPI schema enhancements — full examples on every endpoint
"""

from __future__ import annotations

import asyncio
import base64
import csv
import hashlib
import hmac
import io
import ipaddress
import json
import re
import time
import uuid
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Any, AsyncGenerator, Dict, List, Optional, Set, Tuple

import httpx
from fastapi import (
    APIRouter, BackgroundTasks, Body, Depends, Header,
    HTTPException, Query, Request, WebSocket, WebSocketDisconnect, status,
)
from fastapi.responses import Response, StreamingResponse
from loguru import logger
from prometheus_client import Counter, Gauge, Histogram, Summary
from pydantic import BaseModel, Field, field_validator
from slowapi import Limiter
from slowapi.util import get_remote_address

from ..config import get_settings
from ..db import db
from .auth import get_current_user

# =============================================================================
# Router & settings
# =============================================================================

limiter  = Limiter(key_func=get_remote_address)
router   = APIRouter(prefix="/threats", tags=["Threats"])
settings = get_settings()

# =============================================================================
# ── Prometheus metrics (extended) ─────────────────────────────────────────────
# =============================================================================

query_duration = Histogram(
    "threats_query_duration_seconds",
    "Latency of threat API operations.",
    ["operation"],
    buckets=[.001, .005, .01, .025, .05, .1, .25, .5, 1, 2.5, 5, 10],
)
errors_total    = Counter("threats_errors_total",     "Errors.",                ["operation", "error_type"])
cache_hits      = Counter("threats_cache_hits_total", "Cache hits.",            ["layer"])   # "redis" | "local"
cache_misses    = Counter("threats_cache_misses_total","Cache misses.")
ws_connected    = Gauge("threats_ws_connections",     "Active WS connections.", ["feed"])
intel_errors    = Counter("threats_intel_errors_total","Intel errors.",         ["source"])
exports_total   = Counter("threats_exports_total",    "Exports.",               ["format"])
ai_calls_total  = Counter("threats_ai_calls_total",   "AI service calls.",      ["service", "status"])
rate_limit_hits = Counter("threats_rate_limit_hits",  "Rate limit hits.",       ["tier"])
twin_sims_total = Counter("threats_digital_twin_sims","Digital twin sims.",     ["severity"])
profile_builds  = Counter("threats_profiles_built",   "Attacker profiles.")
risk_scores_p95 = Summary("threats_risk_score",       "Risk score distribution.")

# =============================================================================
# ── Enums & Pydantic models ────────────────────────────────────────────────────
# =============================================================================

class Severity(str, Enum):
    CRITICAL = "critical"; HIGH = "high"; MEDIUM = "medium"; LOW = "low"; INFO = "info"

class SortOrder(str, Enum):
    ASC = "asc"; DESC = "desc"

class AttackType(str, Enum):
    SYN_FLOOD     = "SYN_FLOOD";     PORT_SCAN    = "PORT_SCAN"
    ETCS_SPOOFING = "ETCS_SPOOFING"; MVB_REPLAY   = "MVB_REPLAY"
    TRDP_INJECT   = "TRDP_INJECT";   C2_BEACON    = "C2_BEACON"
    LATERAL_MOVE  = "LATERAL_MOVEMENT"; DATA_EXFIL = "DATA_EXFILTRATION"
    BRUTE_FORCE   = "BRUTE_FORCE";   UNKNOWN      = "UNKNOWN"

class APIKeyCreate(BaseModel):
    name:         str          = Field(..., max_length=80)
    scopes:       List[str]    = Field(default=["threats:read"])
    expires_days: int          = Field(default=365, ge=1, le=3650)
    ip_allowlist: List[str]    = Field(default=[],  description="CIDR ranges allowed to use this key")

class ThreatHuntQuery(BaseModel):
    query:  str = Field(..., description='DSL: src_ip:10.0.* AND score>0.8 AND attack_type:PORT_SCAN')
    limit:  int = Field(default=100, ge=1, le=1000)
    cursor: Optional[str] = Field(default=None, description="Keyset cursor for pagination")

class NLSearchQuery(BaseModel):
    question: str  = Field(..., description="Natural language: 'show me all Lazarus attacks today'")
    limit:    int  = Field(default=50, ge=1, le=200)

class ZeroDayRequest(BaseModel):
    support_examples: List[Dict[str, Any]] = Field(..., description="1-5 labeled attack examples")
    query_features:   List[List[float]]    = Field(..., description="Feature vectors to score")

class WebhookCreate(BaseModel):
    url:          str       = Field(..., description="HTTPS URL to POST alerts to")
    secret:       str       = Field(..., description="HMAC secret for request signing")
    min_score:    float     = Field(default=0.8, ge=0, le=1)
    attack_types: List[str] = Field(default=[])
    active:       bool      = True

class IncidentSummaryRequest(BaseModel):
    threat_ids: List[str] = Field(..., description="Threat IDs to summarize into incident")

# RFC 7807 Problem Details
class ProblemDetail(BaseModel):
    type:     str = "about:blank"
    title:    str
    status:   int
    detail:   str
    instance: Optional[str] = None


def problem(status_code: int, title: str, detail: str, request: Request) -> HTTPException:
    """Returns RFC 7807 Problem Details HTTPException."""
    body = ProblemDetail(
        title=title, status=status_code, detail=detail,
        instance=str(request.url)
    ).model_dump()
    return HTTPException(
        status_code=status_code,
        detail=body,
        headers={"Content-Type": "application/problem+json"},
    )


# =============================================================================
# ── Multi-tier Rate Limiter ────────────────────────────────────────────────────
# =============================================================================

class MultiTierRateLimiter:
    """
    Three-tier sliding window rate limiting:
      Tier 1 (IP):   100 req/min — blocks scrapers
      Tier 2 (User): 500 req/min — per-user budget
      Tier 3 (Org):  2000 req/min — per-organization budget

    Critical alerts (score > 0.95) bypass all limits.
    Adaptive: if p99 latency > 500ms, halve limits for 60s.
    """

    def __init__(self):
        self._degraded   = False
        self._degrade_until = 0.0
        self._limits = {
            "ip":   (100,  60),   # (requests, window_seconds)
            "user": (500,  60),
            "org":  (2000, 60),
        }

    async def check(
        self,
        ip:       str,
        user_id:  str,
        org_id:   str,
        is_critical: bool = False,
    ) -> None:
        """Raises 429 if any tier is exceeded. Critical alerts bypass."""
        if is_critical:
            return

        # Adaptive degradation
        if self._degraded and time.time() > self._degrade_until:
            self._degraded = False

        factor = 0.5 if self._degraded else 1.0

        for key, (limit, window) in [
            (f"rl:ip:{ip}", self._limits["ip"]),
            (f"rl:user:{user_id}", self._limits["user"]),
            (f"rl:org:{org_id}", self._limits["org"]),
        ]:
            effective_limit = int(limit * factor)
            try:
                pipe = db.redis.pipeline()
                pipe.incr(key)
                pipe.expire(key, window)
                results = await pipe.execute()
                count = results[0]
            except Exception:
                continue   # Redis down → fail open

            if count > effective_limit:
                tier = key.split(":")[1]
                rate_limit_hits.labels(tier=tier).inc()
                raise HTTPException(
                    status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                    detail=f"Rate limit exceeded ({tier}): {effective_limit} req/{window}s",
                    headers={"Retry-After": str(window), "X-RateLimit-Tier": tier},
                )

    def signal_degraded(self, duration_s: float = 60.0) -> None:
        self._degraded    = True
        self._degrade_until = time.time() + duration_s
        logger.warning(f"Rate limiter degraded for {duration_s}s (high latency)")


_rate_limiter = MultiTierRateLimiter()

# =============================================================================
# ── Request ID middleware helper ───────────────────────────────────────────────
# =============================================================================

def get_request_id(request: Request) -> str:
    return request.headers.get("X-Request-ID") or str(uuid.uuid4())[:8]

# =============================================================================
# ── Caching (Redis + in-memory) ────────────────────────────────────────────────
# =============================================================================

_local_cache: Dict[str, Dict] = {}
_CACHE_TTL   = 30
_INTEL_TTL   = 3600
_STATS_TTL   = 60


def _cache_key(prefix: str, params: Dict[str, Any]) -> str:
    raw = json.dumps(params, sort_keys=True, default=str)
    return f"{prefix}:{hashlib.sha256(raw.encode()).hexdigest()[:16]}"


async def cache_get(key: str, ttl: int = _CACHE_TTL) -> Optional[Any]:
    try:
        val = await db.redis.get(key)
        if val:
            cache_hits.labels(layer="redis").inc()
            return json.loads(val)
    except Exception:
        pass
    entry = _local_cache.get(key)
    if entry and time.time() - entry["ts"] < ttl:
        cache_hits.labels(layer="local").inc()
        return entry["value"]
    cache_misses.inc()
    return None


async def cache_set(key: str, value: Any, ttl: int = _CACHE_TTL) -> None:
    payload = json.dumps(value, default=str)
    try:
        await db.redis.setex(key, ttl, payload)
    except Exception:
        pass
    _local_cache[key] = {"ts": time.time(), "value": value}


async def cache_invalidate(pattern: str) -> None:
    """Invalidate cache keys matching pattern (Redis SCAN)."""
    try:
        cursor = 0
        while True:
            cursor, keys = await db.redis.scan(cursor, match=pattern, count=100)
            if keys:
                await db.redis.delete(*keys)
            if cursor == 0:
                break
    except Exception as e:
        logger.debug(f"Cache invalidate error: {e}")


async def cache_publish(channel: str, message: Dict) -> None:
    try:
        await db.redis.publish(channel, json.dumps(message, default=str))
    except Exception as e:
        logger.debug(f"Redis publish failed: {e}")

# =============================================================================
# ── Security helpers ───────────────────────────────────────────────────────────
# =============================================================================

import secrets as _secrets


def _mask_ip(ip: str, is_admin: bool) -> str:
    """Field-level PII masking: non-admins see last octet masked."""
    if is_admin:
        return ip
    parts = ip.split(".")
    if len(parts) == 4:
        return f"{parts[0]}.{parts[1]}.{parts[2]}.*"
    return ip[:ip.rfind(":")+1] + "****"   # IPv6


def _sign_webhook_payload(payload: bytes, secret: str) -> str:
    """HMAC-SHA256 signature for webhook consumers."""
    return "sha256=" + hmac.new(
        secret.encode(), payload, hashlib.sha256
    ).hexdigest()


def _check_ip_allowlist(ip: str, allowlist: List[str]) -> bool:
    """Returns True if ip is in any of the CIDR ranges."""
    if not allowlist:
        return True
    try:
        addr = ipaddress.ip_address(ip)
        return any(addr in ipaddress.ip_network(cidr, strict=False) for cidr in allowlist)
    except ValueError:
        return False

# =============================================================================
# ── API Key Auth (v2 + allowlist + idempotency) ────────────────────────────────
# =============================================================================

class APIKeyAuth:
    async def __call__(
        self,
        request:     Request,
        x_api_key:   Optional[str] = Header(None),
        idempotency: Optional[str] = Header(None, alias="Idempotency-Key"),
        user = Depends(get_current_user),
    ):
        if x_api_key:
            key_hash = hashlib.pbkdf2_hmac(
                "sha256", x_api_key.encode(), b"shadow-ndr-v3", 100_000
            ).hex()
            row = await db.pg.fetchrow(
                "SELECT user_id, scopes, expires_at, is_revoked, ip_allowlist, org_id "
                "FROM api_keys WHERE key_hash=$1",
                key_hash,
            )
            if not row:
                raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid API key")
            if row["is_revoked"]:
                raise HTTPException(status.HTTP_401_UNAUTHORIZED, "API key revoked")
            if row["expires_at"] and row["expires_at"] < datetime.now(timezone.utc):
                raise HTTPException(status.HTTP_401_UNAUTHORIZED, "API key expired")

            # IP allowlist check
            allowlist = json.loads(row["ip_allowlist"] or "[]")
            client_ip = request.client.host if request.client else ""
            if not _check_ip_allowlist(client_ip, allowlist):
                raise HTTPException(status.HTTP_403_FORBIDDEN,
                                    f"IP {client_ip} not in API key allowlist")

            auth_ctx = {
                "user_id":  row["user_id"],
                "scopes":   json.loads(row["scopes"]),
                "org_id":   row["org_id"] or "default",
                "is_admin": "admin" in json.loads(row["scopes"]),
            }
        else:
            auth_ctx = {**user, "is_admin": user.get("role") == "admin"}

        # Idempotency key dedup
        if idempotency:
            idem_key = f"idem:{auth_ctx['user_id']}:{idempotency}"
            cached   = await cache_get(idem_key, ttl=86400)
            if cached:
                return Response(
                    content=json.dumps(cached, default=str),
                    media_type="application/json",
                    headers={"X-Idempotent-Replayed": "true"},
                )
            request.state.idempotency_key    = idem_key
            request.state.store_idempotency  = True
        else:
            request.state.store_idempotency = False

        request.state.auth = auth_ctx
        return auth_ctx


api_key_auth = APIKeyAuth()


@router.post("/api-keys", summary="Create API key", status_code=201)
async def create_api_key(
    request: Request,
    body:    APIKeyCreate,
    user = Depends(get_current_user),
) -> Dict[str, Any]:
    raw_key  = f"sndr_{_secrets.token_urlsafe(32)}"
    key_hash = hashlib.pbkdf2_hmac(
        "sha256", raw_key.encode(), b"shadow-ndr-v3", 100_000
    ).hex()
    expires = datetime.now(timezone.utc) + timedelta(days=body.expires_days)
    await db.pg.execute(
        "INSERT INTO api_keys (key_hash, user_id, org_id, name, scopes, expires_at, "
        "is_revoked, ip_allowlist) VALUES ($1,$2,$3,$4,$5,$6,false,$7)",
        key_hash, user["user_id"], user.get("org_id","default"),
        body.name, json.dumps(body.scopes), expires,
        json.dumps(body.ip_allowlist),
    )
    asyncio.create_task(_audit(user["user_id"], "api_key.create", body.name,
                                request.client.host if request.client else ""))
    return {
        "key":         raw_key,
        "expires_at":  expires.isoformat(),
        "scopes":      body.scopes,
        "ip_allowlist": body.ip_allowlist,
        "warning":     "Store securely — this key will not be shown again.",
    }

# =============================================================================
# ── Threat Intelligence Aggregator ────────────────────────────────────────────
# =============================================================================

class ThreatIntelAggregator:
    async def get_intel(self, ip: str) -> Dict[str, Any]:
        ck = f"intel:{ip}"
        cached = await cache_get(ck, ttl=_INTEL_TTL)
        if cached:
            return cached

        results = await asyncio.gather(
            self._abuseipdb(ip), self._otx(ip),
            self._virustotal(ip), self._crowdsec(ip),
            return_exceptions=True,
        )
        merged = {"ip": ip, "abuse_score": 0, "is_tor": False, "is_vpn": False,
                  "country": None, "asn": None, "sources": [], "tags": []}
        for r in results:
            if isinstance(r, Exception) or not r:
                continue
            merged["abuse_score"] = max(merged["abuse_score"], r.get("abuse_score", 0))
            merged["is_tor"]    = merged["is_tor"]  or r.get("is_tor", False)
            merged["is_vpn"]    = merged["is_vpn"]  or r.get("is_vpn", False)
            merged["country"]   = merged["country"] or r.get("country")
            merged["asn"]       = merged["asn"]     or r.get("asn")
            merged["sources"].append(r.get("source", "?"))
            merged["tags"].extend(r.get("tags", []))
        merged["tags"] = list(set(merged["tags"]))
        await cache_set(ck, merged, ttl=_INTEL_TTL)
        return merged

    async def _abuseipdb(self, ip: str) -> Optional[Dict]:
        if not getattr(settings, "ABUSEIPDB_KEY", None): return None
        try:
            async with httpx.AsyncClient(timeout=3.) as c:
                r = await c.get("https://api.abuseipdb.com/api/v2/check",
                                headers={"Key": settings.ABUSEIPDB_KEY, "Accept": "application/json"},
                                params={"ipAddress": ip, "maxAgeInDays": 90})
                if r.status_code == 200:
                    d = r.json().get("data", {})
                    return {"source": "abuseipdb", "abuse_score": d.get("abuseConfidenceScore", 0),
                            "is_tor": d.get("isTor", False), "country": d.get("countryCode"), "tags": []}
        except Exception as e:
            intel_errors.labels(source="abuseipdb").inc(); logger.debug(f"AbuseIPDB: {e}")
        return None

    async def _otx(self, ip: str) -> Optional[Dict]:
        if not getattr(settings, "OTX_KEY", None): return None
        try:
            async with httpx.AsyncClient(timeout=3.) as c:
                r = await c.get(f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general",
                                headers={"X-OTX-API-KEY": settings.OTX_KEY})
                if r.status_code == 200:
                    d = r.json(); tags = [p.get("name") for p in d.get("pulse_info",{}).get("pulses",[])]
                    return {"source": "otx", "abuse_score": min(len(tags)*15, 100), "tags": tags[:10]}
        except Exception as e:
            intel_errors.labels(source="otx").inc(); logger.debug(f"OTX: {e}")
        return None

    async def _virustotal(self, ip: str) -> Optional[Dict]:
        if not getattr(settings, "VT_KEY", None): return None
        try:
            async with httpx.AsyncClient(timeout=3.) as c:
                r = await c.get(f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
                                headers={"x-apikey": settings.VT_KEY})
                if r.status_code == 200:
                    s = r.json().get("data",{}).get("attributes",{}).get("last_analysis_stats",{})
                    mal = s.get("malicious", 0); tot = sum(s.values()) or 1
                    return {"source": "virustotal", "abuse_score": int(mal/tot*100),
                            "tags": ["malicious"] if mal > 0 else []}
        except Exception as e:
            intel_errors.labels(source="virustotal").inc(); logger.debug(f"VT: {e}")
        return None

    async def _crowdsec(self, ip: str) -> Optional[Dict]:
        if not getattr(settings, "CROWDSEC_KEY", None): return None
        try:
            async with httpx.AsyncClient(timeout=3.) as c:
                r = await c.get(f"https://cti.api.crowdsec.net/v2/smoke/{ip}",
                                headers={"x-api-key": settings.CROWDSEC_KEY})
                if r.status_code == 200:
                    d = r.json(); score = d.get("scores",{}).get("overall",{}).get("total",0)*100
                    cls = d.get("classifications",{}).get("classifications",[])
                    tags = [c_.get("name","") for c_ in cls]
                    return {"source": "crowdsec", "abuse_score": int(score),
                            "is_tor": any("tor" in t.lower() for t in tags),
                            "is_vpn": any("vpn" in t.lower() for t in tags), "tags": tags}
        except Exception as e:
            intel_errors.labels(source="crowdsec").inc(); logger.debug(f"CrowdSec: {e}")
        return None


_threat_intel = ThreatIntelAggregator()

# =============================================================================
# ── Risk Scoring Engine ────────────────────────────────────────────────────────
# =============================================================================

class RiskScoringEngine:
    """
    Composite risk score: 0–100
    Factors (weighted):
      ML anomaly score   40%
      Asset criticality  25%
      Threat intel score 20%
      Time-of-day risk   10%   (night/weekend = higher)
      Attack complexity   5%   (# techniques × confidence)
    """

    _ASSET_CRITICALITY: Dict[str, float] = {
        "192.168.100.":   1.0,    # Flight Operations / cockpit uplink
        "10.0.100.":      0.9,    # Airport ground / ATC equipment
        "172.16.":        0.6,    # Airline corporate network
    }

    def compute(
        self,
        ml_score:        float,
        src_ip:          str,
        dst_ip:          str,
        intel:           Optional[Dict],
        attack_types:    List[str],
        timestamp:       Optional[datetime] = None,
    ) -> Dict[str, float]:
        # Asset criticality
        asset_crit = 0.3
        for prefix, crit in self._ASSET_CRITICALITY.items():
            if dst_ip.startswith(prefix):
                asset_crit = crit; break

        # Threat intel score
        intel_score = 0.0
        if intel:
            intel_score = intel.get("abuse_score", 0) / 100
            if intel.get("is_tor"):   intel_score = min(intel_score + 0.2, 1.0)
            if intel.get("is_vpn"):   intel_score = min(intel_score + 0.1, 1.0)

        # Time-of-day risk
        now = timestamp or datetime.utcnow()
        hour = now.hour
        # Night (22:00–06:00) or weekend → elevated
        is_off_hours = hour < 6 or hour >= 22 or now.weekday() >= 5
        time_risk = 0.8 if is_off_hours else 0.4

        # Attack complexity
        n_techniques = len(attack_types)
        complexity = min(n_techniques / 5, 1.0)

        # Composite
        composite = (
            0.40 * ml_score +
            0.25 * asset_crit +
            0.20 * intel_score +
            0.10 * time_risk +
            0.05 * complexity
        )
        risk_100 = round(composite * 100, 1)
        risk_scores_p95.observe(composite)

        return {
            "risk_score":      risk_100,
            "ml_score":        round(ml_score * 100, 1),
            "asset_crit":      round(asset_crit * 100, 1),
            "intel_score":     round(intel_score * 100, 1),
            "time_risk":       round(time_risk * 100, 1),
            "complexity":      round(complexity * 100, 1),
            "is_off_hours":    is_off_hours,
        }


_risk_engine = RiskScoringEngine()

# =============================================================================
# ── GeoIP enrichment ──────────────────────────────────────────────────────────
# =============================================================================

async def enrich_geo(ip: str) -> Optional[Dict[str, Any]]:
    ck = f"geo:{ip}"
    cached = await cache_get(ck, ttl=86400)
    if cached: return cached
    try:
        import geoip2.database  # type: ignore
        with geoip2.database.Reader(settings.GEOIP_DB_PATH) as reader:
            c = reader.city(ip)
            result = {"lat": c.location.latitude, "lon": c.location.longitude,
                      "country": c.country.iso_code, "city": c.city.name, "asn": None}
            await cache_set(ck, result, ttl=86400)
            return result
    except Exception:
        pass
    try:
        async with httpx.AsyncClient(timeout=2.) as c:
            r = await c.get(f"http://ip-api.com/json/{ip}",
                            params={"fields": "lat,lon,countryCode,city,as,status"})
            if r.status_code == 200:
                d = r.json()
                if d.get("status") == "success":
                    result = {"lat": d.get("lat"), "lon": d.get("lon"),
                              "country": d.get("countryCode"), "city": d.get("city"),
                              "asn": d.get("as")}
                    await cache_set(ck, result, ttl=86400)
                    return result
    except Exception: pass
    return None

# =============================================================================
# ── Attack Chain Correlation ───────────────────────────────────────────────────
# =============================================================================

class AttackChain:
    KILL_CHAIN_PATTERNS: List[List[str]] = [
        ["PORT_SCAN", "BRUTE_FORCE", "LATERAL_MOVEMENT"],
        ["PORT_SCAN", "ETCS_SPOOFING"],
        ["C2_BEACON", "DATA_EXFILTRATION"],
        ["PORT_SCAN", "TRDP_INJECT", "MVB_REPLAY"],
    ]

    def correlate(self, threats: List[Dict], window_minutes: int = 30) -> List[Dict]:
        chains: Dict[str, Dict] = {}
        ip_chains: Dict[str, str] = {}
        for t in sorted(threats, key=lambda x: x.get("timestamp", "")):
            src_ip = t.get("src_ip", ""); attack_types = t.get("attack_types", [])
            chain_id = ip_chains.get(src_ip)
            if chain_id and chain_id in chains:
                chain    = chains[chain_id]
                last_ts  = _parse_ts(chain["events"][-1].get("timestamp",""))
                curr_ts  = _parse_ts(t.get("timestamp",""))
                if last_ts and curr_ts and (curr_ts-last_ts).seconds < window_minutes*60:
                    chain["events"].append(t); chain["attack_types"].update(attack_types)
                    chain["risk_score"] = max(chain["risk_score"], t.get("score",0)); continue
            new_id = str(uuid.uuid4())[:8]
            chains[new_id] = {"chain_id": new_id, "src_ip": src_ip, "events": [t],
                              "attack_types": set(attack_types), "risk_score": t.get("score",0),
                              "pattern_match": None}
            ip_chains[src_ip] = new_id
        result = []
        for chain in chains.values():
            types_seq = list(chain["attack_types"])
            for pattern in self.KILL_CHAIN_PATTERNS:
                if all(p in types_seq for p in pattern):
                    chain["pattern_match"] = " → ".join(pattern)
                    chain["risk_score"]    = min(chain["risk_score"]*1.3, 1.0); break
            chain["attack_types"] = list(chain["attack_types"])
            chain["event_count"]  = len(chain["events"])
            result.append(chain)
        return sorted(result, key=lambda c: c["risk_score"], reverse=True)


_chain_correlator = AttackChain()

# =============================================================================
# ── Threat Trajectory Predictor ───────────────────────────────────────────────
# =============================================================================

class ThreatTrajectoryPredictor:
    """
    Predicts where an attacker will move next based on:
      - Current MITRE technique sequence
      - Kill-chain stage
      - Network topology (if digital twin available)

    Returns: list of {next_target, next_technique, probability}
    """

    # MITRE ATT&CK kill-chain transitions (simplified)
    _TRANSITIONS: Dict[str, List[Tuple[str, str, float]]] = {
        "T1046": [("T1110", "Brute Force next service", 0.65),
                  ("T1021", "Remote service exploitation", 0.55)],
        "T1110": [("T1078", "Valid accounts compromise",  0.70),
                  ("T1021", "Lateral movement",           0.60)],
        "T1021": [("T1041", "Data exfiltration",          0.55),
                  ("T1071", "C2 channel setup",           0.50)],
        "T0855": [("T0856", "MVB message replay",         0.75),
                  ("T0836", "Parameter manipulation",     0.65)],
    }

    def predict(
        self,
        techniques:  List[str],
        src_ip:      str,
        network_ips: List[str],
    ) -> List[Dict[str, Any]]:
        predictions = []
        for t in techniques:
            for next_technique, description, prob in self._TRANSITIONS.get(t, []):
                target = network_ips[0] if network_ips else "unknown"
                predictions.append({
                    "from_technique": t,
                    "next_technique": next_technique,
                    "description":    description,
                    "probability":    prob,
                    "likely_target":  target,
                })
        return sorted(predictions, key=lambda x: x["probability"], reverse=True)[:5]


_trajectory_predictor = ThreatTrajectoryPredictor()

# =============================================================================
# ── AI Services (NL search + incident summary) ─────────────────────────────────
# =============================================================================

async def nl_to_dsl(question: str) -> str:
    """
    Converts natural language to threat DSL using ML service.
    Falls back to keyword extraction.
    Examples:
      "show me all Lazarus attacks today" → "attack_type:C2_BEACON AND score>0.7"
      "critical threats from Russia"     → "score>0.9 AND is_critical:true"
    """
    try:
        async with httpx.AsyncClient(timeout=5.) as c:
            r = await c.post(f"{settings.ML_URL}/nl_to_dsl",
                             json={"question": question})
            if r.status_code == 200:
                ai_calls_total.labels(service="nl_to_dsl", status="ok").inc()
                return r.json().get("dsl", "score>0.5")
    except Exception:
        ai_calls_total.labels(service="nl_to_dsl", status="error").inc()

    # Keyword fallback
    dsl_parts = []
    q = question.lower()
    if "critical" in q:          dsl_parts.append("is_critical:true")
    if "lazarus" in q:           dsl_parts.append("attack_type:C2_BEACON AND score>0.7")
    if "etcs" in q:              dsl_parts.append("attack_type:ETCS_SPOOFING")
    if "scan" in q:              dsl_parts.append("attack_type:PORT_SCAN")
    if "score" not in q:         dsl_parts.append("score>0.5")
    return " AND ".join(dsl_parts) or "score>0.5"


async def generate_incident_summary(threats: List[Dict]) -> str:
    """
    GPT-4o-mini generates a 3-sentence executive brief.
    Fallback: template-based summary.
    """
    if not threats:
        return "No threats to summarize."

    top_threats = threats[:10]
    scores      = [t.get("score", 0) for t in top_threats]
    ips         = list({t.get("src_ip") for t in top_threats})[:3]
    types_set   = list({at for t in top_threats for at in t.get("attack_types", [])})[:3]
    avg_score   = sum(scores) / len(scores)

    try:
        prompt = (
            f"Write a 3-sentence executive security brief about the following threats:\n"
            f"- {len(threats)} total threats detected\n"
            f"- Average anomaly score: {avg_score:.2f}\n"
            f"- Source IPs: {', '.join(ips)}\n"
            f"- Attack types: {', '.join(types_set)}\n"
            f"Be concise, professional, action-oriented."
        )
        async with httpx.AsyncClient(timeout=8.) as c:
            r = await c.post(
                "https://api.openai.com/v1/chat/completions",
                headers={"Authorization": f"Bearer {getattr(settings,'OPENAI_KEY','')}"},
                json={"model": "gpt-4o-mini", "messages": [{"role":"user","content":prompt}],
                      "temperature": 0.3, "max_tokens": 200},
            )
            if r.status_code == 200:
                ai_calls_total.labels(service="incident_summary", status="ok").inc()
                return r.json()["choices"][0]["message"]["content"].strip()
    except Exception:
        ai_calls_total.labels(service="incident_summary", status="error").inc()

    # Template fallback
    severity = "CRITICAL" if avg_score > 0.85 else "HIGH" if avg_score > 0.65 else "MEDIUM"
    return (
        f"{severity} ALERT: {len(threats)} anomalous events detected from {len(ips)} source IPs "
        f"(avg score {avg_score:.2f}). "
        f"Primary attack techniques: {', '.join(types_set) or 'unknown'}. "
        f"Immediate investigation of top source IPs recommended."
    )

# =============================================================================
# ── Threat Hunt DSL ───────────────────────────────────────────────────────────
# =============================================================================

class ThreatHuntDSL:
    _TOKEN_RE = re.compile(
        r"(?P<field>[a-z_]+)(?P<op>[><=!:~]+)(?P<value>\S+)|(?P<bool>AND|OR)",
        re.IGNORECASE,
    )

    def parse(self, query: str) -> Tuple[str, Dict[str, Any]]:
        clauses: List[str] = []; connectors: List[str] = []; params: Dict[str, Any] = {}; idx = 0
        for m in self._TOKEN_RE.finditer(query):
            if m.group("bool"):
                connectors.append(m.group("bool").upper()); continue
            field = m.group("field").lower(); op = m.group("op"); value = m.group("value")
            p = f"p_{idx}"; idx += 1
            clause = self._clause(field, op, value, p, params)
            if clause:
                if clauses:
                    clauses.append(connectors.pop(0) if connectors else "AND")
                clauses.append(clause)
        if not clauses:
            raise ValueError(f"Unparseable DSL: {query!r}")
        return " ".join(clauses), params

    def _clause(self, field, op, value, p, params):
        if field == "score":
            try: params[p] = float(value)
            except ValueError: raise ValueError(f"Invalid score: {value!r}")
            op_map = {">":">","<":"<",">=":">=","<=":"<=","=":"=","==":"=","!=":"!=",":":"="}
            return f"score {op_map.get(op,'=')} %({p})s"
        if field in ("is_critical",):
            params[p] = 1 if value.lower() in ("true","1","yes") else 0
            return f"{field} = %({p})s"
        if field in ("src_ip","dst_ip"):
            if "/" in value:
                params[p] = value
                return f"isIPAddressInRange({field}, %({p})s)"
            elif "*" in value:
                params[p] = value.replace("*","%")
                return f"{field} LIKE %({p})s"
            else:
                params[p] = value; return f"{field} = %({p})s"
        if field == "attack_type":
            params[p] = f'"{value}"'
            return f"has(JSONExtractArrayRaw(attack_types), %({p})s)"
        if op == "~":
            try: re.compile(value)
            except re.error as e: raise ValueError(f"Bad regex: {e}")
            params[p] = value; return f"match({field}, %({p})s)"
        params[p] = value; return f"{field} = %({p})s"


_dsl_parser = ThreatHuntDSL()

# =============================================================================
# ── WHERE builder ─────────────────────────────────────────────────────────────
# =============================================================================

def _build_where(
    params: Dict[str, Any],
    severity: Optional[Severity] = None,
    attack_type: Optional[str] = None,
    src_ip: Optional[str] = None, dst_ip: Optional[str] = None,
    src_cidr: Optional[str] = None, dst_cidr: Optional[str] = None,
    src_regex: Optional[str] = None,
    min_score: Optional[float] = None, max_score: Optional[float] = None,
    org_id: str = "", start_time: Optional[datetime] = None,
    end_time: Optional[datetime] = None,
) -> str:
    clauses = ["org_id = %(org_id)s", "timestamp >= %(start_time)s", "timestamp < %(end_time)s"]
    params.update({"org_id": org_id,
                   "start_time": start_time or datetime.utcnow() - timedelta(days=7),
                   "end_time":   end_time   or datetime.utcnow()})
    if severity:
        clauses.append({
            Severity.CRITICAL: "is_critical = 1",
            Severity.HIGH:     "score > 0.8 AND is_critical = 0",
            Severity.MEDIUM:   "score > 0.5 AND score <= 0.8",
            Severity.LOW:      "score > 0.3 AND score <= 0.5",
            Severity.INFO:     "score <= 0.3",
        }[severity])
    if attack_type:
        clauses.append("has(JSONExtractArrayRaw(attack_types), %(attack_type)s)")
        params["attack_type"] = f'"{attack_type}"'
    if src_ip:   clauses.append("src_ip = %(src_ip)s"); params["src_ip"] = src_ip
    if dst_ip:   clauses.append("dst_ip = %(dst_ip)s"); params["dst_ip"] = dst_ip
    if src_cidr:
        try: ipaddress.ip_network(src_cidr, strict=False)
        except ValueError: pass
        else: clauses.append("isIPAddressInRange(src_ip, %(src_cidr)s)"); params["src_cidr"] = src_cidr
    if dst_cidr:
        try: ipaddress.ip_network(dst_cidr, strict=False)
        except ValueError: pass
        else: clauses.append("isIPAddressInRange(dst_ip, %(dst_cidr)s)"); params["dst_cidr"] = dst_cidr
    if src_regex:
        try: re.compile(src_regex)
        except re.error: pass
        else: clauses.append("match(src_ip, %(src_regex)s)"); params["src_regex"] = src_regex
    if min_score is not None: clauses.append("score >= %(min_score)s"); params["min_score"] = min_score
    if max_score is not None: clauses.append("score <= %(max_score)s"); params["max_score"] = max_score
    return "WHERE " + " AND ".join(clauses)


def _severity(score: float, is_critical: bool) -> str:
    if is_critical: return "critical"
    if score > 0.8: return "high"
    if score > 0.5: return "medium"
    if score > 0.3: return "low"
    return "info"


def _row_to_threat(row: tuple, is_admin: bool = True) -> Dict[str, Any]:
    attack_types = json.loads(row[4]) if row[4] else []
    is_critical  = row[5] == 1; score = float(row[3])
    src_ip = row[1]
    return {
        "timestamp":    row[0].isoformat() if hasattr(row[0], "isoformat") else str(row[0]),
        "src_ip":       _mask_ip(src_ip, is_admin),
        "dst_ip":       row[2],
        "score":        score,
        "attack_types": attack_types,
        "is_critical":  is_critical,
        "severity":     _severity(score, is_critical),
        "_raw_src_ip":  src_ip,   # internal — stripped before response
    }

# =============================================================================
# ── Audit logging ─────────────────────────────────────────────────────────────
# =============================================================================

async def _audit(user_id: str, action: str, resource: str, request_ip: str = "") -> None:
    try:
        await db.pg.execute(
            "INSERT INTO audit_logs (user_id, action, resource, request_ip, created_at) "
            "VALUES ($1,$2,$3,$4,NOW())",
            user_id, action, resource, request_ip,
        )
    except Exception as e:
        logger.warning(f"Audit write failed: {e}")

# =============================================================================
# ── Webhook delivery ──────────────────────────────────────────────────────────
# =============================================================================

class WebhookDelivery:
    """
    Delivers signed alert payloads to registered webhook URLs.
    Retry: 3 attempts, exponential backoff.
    """

    async def deliver(self, url: str, secret: str, payload: Dict) -> bool:
        body = json.dumps(payload, default=str).encode()
        sig  = _sign_webhook_payload(body, secret)
        for attempt in range(3):
            try:
                async with httpx.AsyncClient(timeout=5.) as c:
                    r = await c.post(url, content=body, headers={
                        "Content-Type":    "application/json",
                        "X-Shadow-Sig":    sig,
                        "X-Delivery-Attempt": str(attempt + 1),
                    })
                    if r.status_code < 300:
                        return True
            except Exception as e:
                logger.debug(f"Webhook attempt {attempt+1} failed: {e}")
            await asyncio.sleep(2 ** attempt)
        return False


_webhook_delivery = WebhookDelivery()

# =============================================================================
# ── WebSocket manager ─────────────────────────────────────────────────────────
# =============================================================================

class ConnectionManager:
    def __init__(self, feed: str):
        self._connections: Set[WebSocket] = set()
        self._feed = feed

    async def connect(self, ws: WebSocket) -> None:
        await ws.accept(); self._connections.add(ws); ws_connected.labels(feed=self._feed).inc()

    def disconnect(self, ws: WebSocket) -> None:
        self._connections.discard(ws); ws_connected.labels(feed=self._feed).dec()

    async def broadcast(self, message: Dict) -> None:
        dead = set()
        for ws in self._connections:
            try: await ws.send_json(message)
            except Exception: dead.add(ws)
        for ws in dead: self.disconnect(ws)


_ws_threats = ConnectionManager("threats")
_ws_live    = ConnectionManager("live")

# =============================================================================
# ── Export helpers ────────────────────────────────────────────────────────────
# =============================================================================

async def _generate_csv(threats: List[Dict]) -> str:
    buf = io.StringIO()
    w   = csv.DictWriter(buf, fieldnames=[
        "timestamp","src_ip","dst_ip","score","attack_types","severity","is_critical","risk_score"
    ])
    w.writeheader()
    for t in threats:
        row = dict(t); row.pop("_raw_src_ip", None)
        row["attack_types"] = ",".join(t.get("attack_types", []))
        w.writerow({k: row.get(k,"") for k in w.fieldnames})
    return buf.getvalue()


async def _bg_export(task_id: str, threats: List[Dict], fmt: str) -> None:
    try:
        if fmt == "csv":
            content = await _generate_csv(threats)
        else:
            content = json.dumps({"threats": threats, "generated_at": datetime.utcnow().isoformat()},
                                  indent=2, default=str)
        await db.redis.setex(f"export:{task_id}",   300, content)
        await db.redis.setex(f"export:{task_id}:status", 300, "ready")
    except Exception as e:
        await db.redis.setex(f"export:{task_id}:status", 300, f"error:{e}")


def _parse_ts(ts_str: str) -> Optional[datetime]:
    try: return datetime.fromisoformat(ts_str.replace("Z","+00:00"))
    except Exception: return None


def _strip_internal(threat: Dict) -> Dict:
    """Remove internal-only fields before sending to client."""
    t = dict(threat); t.pop("_raw_src_ip", None); return t

# =============================================================================
# ══════════════════════════════════════════════════════════════════════════════
# API ENDPOINTS
# ══════════════════════════════════════════════════════════════════════════════
# =============================================================================

# ── WebSockets ────────────────────────────────────────────────────────────────

@router.websocket("/ws")
async def threat_stream(websocket: WebSocket, token: str = ""):
    """
    Real-time threat stream (Redis pub/sub → WS).
    Client config: {"min_score": 0.5, "attack_types": ["PORT_SCAN"]}
    Server push: {"type": "threat", "data": {...}, "profile": {...}}
    """
    await _ws_threats.connect(websocket)
    min_score = 0.0; filter_types: Set[str] = set()
    try:
        try:
            cfg = await asyncio.wait_for(websocket.receive_json(), timeout=5.)
            min_score    = float(cfg.get("min_score", 0.))
            filter_types = set(cfg.get("attack_types", []))
        except Exception: pass
        await websocket.send_json({"type": "connected", "min_score": min_score})
        pubsub = db.redis.pubsub()
        await pubsub.subscribe("threats:new")
        # Heartbeat task
        async def heartbeat():
            while True:
                try: await websocket.send_json({"type": "ping", "ts": time.time()})
                except Exception: break
                await asyncio.sleep(30)
        hb_task = asyncio.create_task(heartbeat())
        async for message in pubsub.listen():
            if message["type"] != "message": continue
            try:
                threat = json.loads(message["data"])
                if threat.get("score", 0) < min_score: continue
                if filter_types and not any(at in filter_types for at in threat.get("attack_types",[])):
                    continue
                await websocket.send_json({"type": "threat", "data": threat})
            except Exception: continue
    except WebSocketDisconnect: pass
    except Exception as e: logger.debug(f"WS threat error: {e}")
    finally:
        if "hb_task" in dir(): hb_task.cancel()
        _ws_threats.disconnect(websocket)


@router.websocket("/live")
async def live_dashboard(websocket: WebSocket):
    """Live dashboard — pushes threats + stats every 5s."""
    await _ws_live.connect(websocket)
    try:
        pubsub = db.redis.pubsub()
        await pubsub.subscribe("threats:new", "threats:stats")
        async for message in pubsub.listen():
            if message["type"] != "message": continue
            try: await websocket.send_json(json.loads(message["data"]))
            except Exception: continue
    except WebSocketDisconnect: pass
    finally: _ws_live.disconnect(websocket)


# ── SSE fallback ──────────────────────────────────────────────────────────────

@router.get("/stream", summary="SSE threat stream (WebSocket fallback)")
async def threat_stream_sse(
    request:   Request,
    min_score: float = Query(0.5, ge=0, le=1),
    user = Depends(api_key_auth),
) -> StreamingResponse:
    """Server-Sent Events fallback for environments that don't support WebSocket."""
    async def event_generator() -> AsyncGenerator[str, None]:
        yield f"data: {json.dumps({'type':'connected','min_score':min_score})}\n\n"
        pubsub = db.redis.pubsub()
        await pubsub.subscribe("threats:new")
        try:
            async for message in pubsub.listen():
                if await request.is_disconnected(): break
                if message["type"] != "message": continue
                try:
                    threat = json.loads(message["data"])
                    if threat.get("score", 0) >= min_score:
                        yield f"data: {json.dumps(threat, default=str)}\n\n"
                except Exception: continue
        except asyncio.CancelledError: pass
    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


# ── GET /threats ──────────────────────────────────────────────────────────────

@router.get("", summary="List threats — full-featured", response_model=None)
@limiter.limit("100/minute")
async def get_threats(
    request:     Request,
    limit:       int   = Query(50,   ge=1,  le=500),
    cursor:      Optional[str]  = Query(None, description="Keyset cursor (opaque, from prev response)"),
    severity:    Optional[Severity]  = None,
    attack_type: Optional[str]       = None,
    src_ip:      Optional[str]       = None,
    dst_ip:      Optional[str]       = None,
    src_cidr:    Optional[str]       = None,
    dst_cidr:    Optional[str]       = None,
    src_regex:   Optional[str]       = None,
    start_time:  Optional[datetime]  = None,
    end_time:    Optional[datetime]  = None,
    min_score:   Optional[float]     = Query(None, ge=0, le=1),
    max_score:   Optional[float]     = Query(None, ge=0, le=1),
    order_by:    str   = Query("timestamp", pattern="^(timestamp|score|src_ip)$"),
    order:       SortOrder = SortOrder.DESC,
    org_id:      Optional[str] = None,
    include_intel:  bool = Query(False),
    include_geo:    bool = Query(False),
    include_risk:   bool = Query(False, description="Include risk breakdown"),
    include_profile: bool = Query(False, description="Include attacker profile (v7)"),
    include_trajectory: bool = Query(False, description="Include threat trajectory prediction"),
    ai_prioritize: bool = Query(False),
    user = Depends(api_key_auth),
) -> Dict[str, Any]:
    """
    Full-featured threat listing.
    New in v3: risk scoring, attacker profiles, threat trajectory,
    keyset pagination, field-level IP masking, request tracing.
    """
    req_id = get_request_id(request)
    auth   = request.state.auth
    is_admin = auth.get("is_admin", False)
    resolved_org = org_id or auth.get("org_id", "default")

    await _rate_limiter.check(
        request.client.host if request.client else "",
        auth.get("user_id",""), resolved_org,
    )

    # Keyset cursor decode
    cursor_filter = ""
    cursor_params: Dict[str, Any] = {}
    if cursor:
        try:
            decoded = json.loads(base64.b64decode(cursor).decode())
            cursor_filter = f"AND (timestamp, src_ip) < (%(cur_ts)s, %(cur_ip)s)"
            cursor_params = {"cur_ts": decoded["ts"], "cur_ip": decoded["ip"]}
        except Exception:
            pass

    ck = _cache_key("threats_v3", {
        "org": resolved_org, "limit": limit, "sev": severity, "at": attack_type,
        "src": src_ip, "dst": dst_ip, "min_s": min_score, "max_s": max_score,
        "ob": order_by, "ord": order, "cursor": cursor,
    })
    hit = await cache_get(ck)
    if hit:
        return {**hit, "x_request_id": req_id, "x_cache": "HIT"}

    t0 = time.time()
    try:
        params: Dict[str, Any] = {}
        where  = _build_where(params, severity=severity, attack_type=attack_type,
                               src_ip=src_ip, dst_ip=dst_ip, src_cidr=src_cidr,
                               dst_cidr=dst_cidr, src_regex=src_regex,
                               min_score=min_score, max_score=max_score,
                               org_id=resolved_org, start_time=start_time, end_time=end_time)
        params.update(cursor_params)
        order_dir = "ASC" if order == SortOrder.ASC else "DESC"
        params["limit"] = limit

        query = f"""
            SELECT timestamp, src_ip, dst_ip, score, attack_types, is_critical
            FROM packets
            {where} {cursor_filter}
            ORDER BY {order_by} {order_dir}
            LIMIT %(limit)s
        """
        count_q = f"SELECT COUNT(*) FROM packets {where}"
        rows, count_row = await asyncio.gather(
            db.clickhouse_execute(query, params),
            db.clickhouse_execute(count_q, params),
        )
        total = count_row[0][0] if count_row else 0

        threats = [_row_to_threat(row, is_admin=is_admin) for row in rows]

        # Build next cursor
        next_cursor = None
        if len(threats) == limit and threats:
            last = threats[-1]
            next_cursor = base64.b64encode(
                json.dumps({"ts": last["timestamp"], "ip": last.get("_raw_src_ip","")},
                           default=str).encode()
            ).decode()

        # Parallel enrichment
        enrich_tasks = []
        top10 = threats[:10]
        if include_intel:
            enrich_tasks += [_threat_intel.get_intel(t["_raw_src_ip"]) for t in top10]
        if include_geo:
            enrich_tasks += [enrich_geo(t["_raw_src_ip"]) for t in top10]

        enrichments = (await asyncio.gather(*enrich_tasks, return_exceptions=True)
                       if enrich_tasks else [])

        n_intel = len(top10) if include_intel else 0
        for i, t in enumerate(top10):
            raw_ip = t["_raw_src_ip"]
            if include_intel and i < n_intel:
                if not isinstance(enrichments[i], Exception):
                    t["threat_intel"] = enrichments[i]
                    # Risk score
                    if include_risk:
                        t["risk"] = _risk_engine.compute(
                            t["score"], raw_ip, t["dst_ip"],
                            enrichments[i], t["attack_types"],
                        )
            if include_geo:
                gi = i + n_intel
                if gi < len(enrichments) and not isinstance(enrichments[gi], Exception):
                    t["geo"] = enrichments[gi]

            # Attacker profile (v7 integration)
            if include_profile:
                intel_data = t.get("threat_intel")
                profile = await _threat_intel.get_intel(raw_ip)
                try:
                    async with httpx.AsyncClient(timeout=3.) as c:
                        r = await c.post(f"{settings.ML_URL}/profile",
                                         json={"src_ip": raw_ip,
                                               "attack_types": t["attack_types"],
                                               "intel": intel_data})
                        if r.status_code == 200:
                            t["attacker_profile"] = r.json()
                            profile_builds.inc()
                except Exception:
                    pass

            # Threat trajectory
            if include_trajectory:
                try:
                    async with httpx.AsyncClient(timeout=2.) as c:
                        r = await c.post(f"{settings.ML_URL}/trajectory",
                                         json={"attack_types": t["attack_types"],
                                               "src_ip": raw_ip})
                        if r.status_code == 200:
                            t["trajectory"] = r.json().get("predictions", [])
                except Exception:
                    pass

        # AI prioritization
        if ai_prioritize:
            try:
                async with httpx.AsyncClient(timeout=3.) as c:
                    r = await c.post(f"{settings.ML_URL}/prioritize",
                                     json={"threats": threats})
                    if r.status_code == 200:
                        threats = r.json().get("ranked_threats", threats)
            except Exception:
                pass

        # Remediation hints for critical
        for t in threats:
            if t.get("score", 0) > 0.8 and t.get("attack_types"):
                t["remediation_hint"] = _PLAYBOOKS.get(
                    t["attack_types"][0], ["Investigate manually"]
                )[:2]   # top 2 steps only in list view

        # Strip internal fields
        threats_clean = [_strip_internal(t) for t in threats]

        resp = {
            "total":       total,
            "limit":       limit,
            "next_cursor": next_cursor,
            "threats":     threats_clean,
            "x_request_id": req_id,
            "x_cache":     "MISS",
        }
        await cache_set(ck, resp)
        asyncio.create_task(_audit(auth.get("user_id",""), "threats.list",
                                   f"count={total}", request.client.host if request.client else ""))

        # Store idempotency result
        if request.state.store_idempotency:
            await cache_set(request.state.idempotency_key, resp, ttl=86400)

        return resp

    except HTTPException: raise
    except Exception as e:
        errors_total.labels(operation="list", error_type=type(e).__name__).inc()
        logger.error(f"[{req_id}] get_threats error: {e}")
        raise problem(500, "Internal Server Error",
                      f"Query failed. Request ID: {req_id}", request)
    finally:
        dur = time.time() - t0
        query_duration.labels(operation="list").observe(dur)
        if dur > 0.5:
            _rate_limiter.signal_degraded(60.)


# ── GET /threats/stats ────────────────────────────────────────────────────────

@router.get("/stats", summary="Aggregated threat statistics")
@limiter.limit("100/minute")
async def get_threat_stats(
    request:  Request,
    hours:    int = Query(24, ge=1, le=168),
    group_by: str = Query("hour", pattern="^(hour|day|attack_type|src_ip)$"),
    user = Depends(api_key_auth),
) -> Dict[str, Any]:
    auth = request.state.auth
    ck   = _cache_key("stats_v3", {"h": hours, "g": group_by, "org": auth.get("org_id","")})
    hit  = await cache_get(ck, ttl=_STATS_TTL)
    if hit: return hit
    t0    = time.time()
    since = datetime.utcnow() - timedelta(hours=hours)
    org   = auth.get("org_id","default")
    _GROUP = {
        "hour": "toStartOfHour(timestamp)",
        "day":  "toStartOfDay(timestamp)",
        "attack_type": "arrayJoin(JSONExtractArrayRaw(attack_types))",
        "src_ip": "src_ip",
    }
    _ORDER = {"hour":"ORDER BY grp","day":"ORDER BY grp",
              "attack_type":"ORDER BY total DESC LIMIT 20","src_ip":"ORDER BY total DESC LIMIT 20"}
    group_expr = _GROUP[group_by]; order_expr = _ORDER[group_by]
    extra_where = "AND attack_types != ''" if group_by == "attack_type" else ""
    query = f"""
        SELECT {group_expr} AS grp, COUNT(*) AS total, AVG(score) AS avg_score,
               MAX(score) AS max_score, COUNTIf(is_critical=1) AS critical,
               COUNTIf(score>0.8) AS high, COUNTIf(score>0.5 AND score<=0.8) AS medium
        FROM packets
        WHERE org_id=%(org_id)s AND timestamp>=%(since)s {extra_where}
        GROUP BY grp {order_expr}
    """
    try:
        rows = await db.clickhouse_execute(query, {"org_id": org, "since": since})
        data = [{"group": row[0].isoformat() if hasattr(row[0],"isoformat") else str(row[0]),
                 "total": row[1], "avg_score": round(float(row[2]),4),
                 "max_score": round(float(row[3]),4), "critical": row[4],
                 "high": row[5], "medium": row[6]} for row in rows]
        result = {"period_hours": hours, "group_by": group_by, "data": data}
        await cache_set(ck, result, ttl=_STATS_TTL)
        return result
    except Exception as e:
        errors_total.labels(operation="stats", error_type=type(e).__name__).inc()
        logger.error(f"stats error: {e}")
        raise HTTPException(500, "Internal server error")
    finally:
        query_duration.labels(operation="stats").observe(time.time()-t0)


# ── GET /threats/predict ──────────────────────────────────────────────────────

@router.get("/predict", summary="Prophet/ARIMA threat rate forecast")
@limiter.limit("20/minute")
async def get_threat_predictions(
    request: Request,
    hours:   int = Query(1, ge=1, le=48),
    user = Depends(api_key_auth),
) -> Dict[str, Any]:
    auth = request.state.auth
    try:
        async with httpx.AsyncClient(timeout=5.) as c:
            r = await c.get(f"{settings.ML_URL}/forecast",
                            params={"hours": hours, "org_id": auth.get("org_id","")})
            if r.status_code == 200:
                ai_calls_total.labels(service="forecast", status="ok").inc()
                return {"period_hours": hours, **r.json()}
    except Exception as e:
        ai_calls_total.labels(service="forecast", status="error").inc()
        logger.warning(f"Forecast unavailable: {e}")
    return {"period_hours": hours, "error": "forecast unavailable",
            "predictions": [], "confidence": 0.0, "degraded": True}


# ── POST /threats/hunt ────────────────────────────────────────────────────────

@router.post("/hunt", summary="DSL threat hunting")
@limiter.limit("30/minute")
async def threat_hunt(
    request: Request,
    body:    ThreatHuntQuery,
    user = Depends(api_key_auth),
) -> Dict[str, Any]:
    auth  = request.state.auth; t0 = time.time()
    try:
        dsl_where, dsl_params = _dsl_parser.parse(body.query)
    except ValueError as e:
        raise problem(400, "DSL Parse Error", str(e), request)
    dsl_params.update({"org_id": auth.get("org_id","default"),
                        "start_time": datetime.utcnow()-timedelta(days=30),
                        "end_time":   datetime.utcnow(), "limit": body.limit})
    query = f"""
        SELECT timestamp, src_ip, dst_ip, score, attack_types, is_critical
        FROM packets
        WHERE org_id=%(org_id)s AND timestamp>=%(start_time)s AND timestamp<%(end_time)s
          AND ({dsl_where})
        ORDER BY score DESC LIMIT %(limit)s
    """
    try:
        rows    = await db.clickhouse_execute(query, dsl_params)
        threats = [_strip_internal(_row_to_threat(r, auth.get("is_admin",False))) for r in rows]
        asyncio.create_task(_audit(auth.get("user_id",""), "threats.hunt", body.query,
                                   request.client.host if request.client else ""))
        return {"query": body.query, "total": len(threats), "threats": threats,
                "latency_ms": round((time.time()-t0)*1000, 1)}
    except Exception as e:
        errors_total.labels(operation="hunt", error_type=type(e).__name__).inc()
        raise problem(500, "Query Execution Failed", str(e), request)


# ── POST /threats/search/nl ───────────────────────────────────────────────────

@router.post("/search/nl", summary="Natural language threat search (AI-powered)")
@limiter.limit("20/minute")
async def nl_search(
    request: Request,
    body:    NLSearchQuery,
    user = Depends(api_key_auth),
) -> Dict[str, Any]:
    """
    Convert natural language to DSL and execute.
    Examples:
      "show me all Lazarus attacks today"
      "critical threats from Eastern Europe last hour"
      "ETCS spoofing attempts this week"
    """
    auth = request.state.auth
    dsl  = await nl_to_dsl(body.question)
    asyncio.create_task(_audit(auth.get("user_id",""), "threats.nl_search", body.question,
                                request.client.host if request.client else ""))
    try:
        dsl_where, dsl_params = _dsl_parser.parse(dsl)
    except ValueError:
        dsl_where, dsl_params = "score > %(p_0)s", {"p_0": 0.5}
    dsl_params.update({"org_id": auth.get("org_id","default"),
                        "start_time": datetime.utcnow()-timedelta(days=7),
                        "end_time": datetime.utcnow(), "limit": body.limit})
    query = f"""
        SELECT timestamp, src_ip, dst_ip, score, attack_types, is_critical
        FROM packets
        WHERE org_id=%(org_id)s AND timestamp>=%(start_time)s AND timestamp<%(end_time)s
          AND ({dsl_where})
        ORDER BY score DESC LIMIT %(limit)s
    """
    rows    = await db.clickhouse_execute(query, dsl_params)
    threats = [_strip_internal(_row_to_threat(r, auth.get("is_admin",False))) for r in rows]
    return {"question": body.question, "interpreted_dsl": dsl,
            "total": len(threats), "threats": threats}


# ── POST /threats/incident/summary ───────────────────────────────────────────

@router.post("/incident/summary", summary="AI-generated incident executive brief")
@limiter.limit("10/minute")
async def incident_summary(
    request: Request,
    body:    IncidentSummaryRequest,
    user = Depends(api_key_auth),
) -> Dict[str, Any]:
    """Generates a 3-sentence executive brief from a list of threat IDs."""
    auth  = request.state.auth
    where = "WHERE org_id=%(org_id)s AND rowid IN %(ids)s"
    # Fetch relevant threats from ClickHouse
    query = f"""
        SELECT timestamp, src_ip, dst_ip, score, attack_types, is_critical
        FROM packets
        WHERE org_id=%(org_id)s
          AND toString(sipHash64(concat(src_ip,dst_ip,toString(timestamp)))) IN %(ids)s
        LIMIT 50
    """
    try:
        rows    = await db.clickhouse_execute(query, {
            "org_id": auth.get("org_id","default"),
            "ids":    tuple(body.threat_ids[:50]) or ("__none__",),
        })
        threats  = [_row_to_threat(r) for r in rows]
        summary  = await generate_incident_summary(threats)
        asyncio.create_task(_audit(auth.get("user_id",""), "incident.summary",
                                   f"ids={len(body.threat_ids)}"))
        return {"summary": summary, "threats_analyzed": len(threats),
                "generated_at": datetime.utcnow().isoformat()}
    except Exception as e:
        logger.error(f"incident summary error: {e}")
        return {"summary": await generate_incident_summary([]), "threats_analyzed": 0}


# ── POST /threats/detect/zero-day ─────────────────────────────────────────────

@router.post("/detect/zero-day", summary="Few-shot zero-day detection (MAML v7)")
@limiter.limit("10/minute")
async def zero_day_detect(
    request: Request,
    body:    ZeroDayRequest,
    user = Depends(api_key_auth),
) -> Dict[str, Any]:
    """
    Detect zero-day attacks using the v7 MAML few-shot model.
    Provide 1–5 labeled examples of the new attack type.
    """
    auth = request.state.auth
    try:
        async with httpx.AsyncClient(timeout=5.) as c:
            r = await c.post(f"{settings.ML_URL}/few_shot_detect",
                             json={"support_examples": body.support_examples,
                                   "query_features": body.query_features})
            if r.status_code == 200:
                ai_calls_total.labels(service="few_shot", status="ok").inc()
                return {"scores": r.json().get("scores", []), "model": "MAML-v7",
                        "n_support": len(body.support_examples)}
    except Exception as e:
        ai_calls_total.labels(service="few_shot", status="error").inc()
        logger.warning(f"Few-shot endpoint unavailable: {e}")
    return {"scores": [0.0]*len(body.query_features), "model": "fallback",
            "n_support": len(body.support_examples), "degraded": True}


# ── GET /threats/chains ───────────────────────────────────────────────────────

@router.get("/chains", summary="MITRE kill-chain correlation")
@limiter.limit("30/minute")
async def get_attack_chains(
    request:    Request,
    hours:      int = Query(6,  ge=1, le=72),
    min_events: int = Query(2,  ge=2, le=50),
    user = Depends(api_key_auth),
) -> Dict[str, Any]:
    auth  = request.state.auth
    since = datetime.utcnow()-timedelta(hours=hours)
    query = """SELECT timestamp,src_ip,dst_ip,score,attack_types,is_critical FROM packets
               WHERE org_id=%(org_id)s AND timestamp>=%(since)s AND score>0.4
               ORDER BY timestamp LIMIT 5000"""
    try:
        rows   = await db.clickhouse_execute(query,{"org_id":auth.get("org_id","default"),"since":since})
        threats= [_row_to_threat(r,auth.get("is_admin",False)) for r in rows]
        chains = _chain_correlator.correlate(threats)
        chains = [c for c in chains if c["event_count"]>=min_events]
        return {"period_hours":hours,"n_chains":len(chains),"chains":chains}
    except Exception as e:
        logger.error(f"chains error: {e}")
        raise HTTPException(500, "Internal server error")


# ── GET /threats/remediation/{attack_type} ────────────────────────────────────

_PLAYBOOKS: Dict[str, List[str]] = {
    "SYN_FLOOD":     ["Block source IP in firewall",  "Enable SYN cookies",
                      "Increase SYN backlog (sysctl)", "Notify NOC"],
    "PORT_SCAN":     ["Quarantine src IP for 1h",     "Review exposed services"],
    "ADS_B_SPOOFING": ["IMMEDIATE: Notify ATC and flight ops", "Cross-check with primary radar / Mode-S",
                        "Preserve packet captures",              "File ICAO / FAA incident report"],
    "ACARS_INJECTION": ["Isolate affected ACARS endpoint",       "Re-auth uplink with datalink provider",
                        "Enable sequence-number monitoring"],
    "MODE_S_REPLAY":   ["Verify Mode-S CRC across receivers",    "Isolate compromised receiver site",
                        "Review FMS logic for unexpected state changes"],
    "C2_BEACON":     ["Block outbound to C2 IP/domain", "Isolate affected host",
                      "Revoke credentials for active accounts", "Report to NCSC"],
    "LATERAL_MOVEMENT": ["Segment affected VLAN", "Reset passwords on src host",
                          "Scan destination hosts for indicators"],
    "DATA_EXFILTRATION":["Block outbound from src IP", "Identify data accessed",
                          "Initiate breach notification if PII involved"],
    "BRUTE_FORCE":   ["Lock account after failures", "Enable MFA", "Add IP to blocklist"],
}


@router.get("/remediation/{attack_type}", summary="Remediation playbook")
async def get_remediation_playbook(
    request:     Request,
    attack_type: str,
    src_ip:      str = Query(""),
    dst_ip:      str = Query(""),
    user = Depends(api_key_auth),
) -> Dict[str, Any]:
    auth  = request.state.auth
    steps = _PLAYBOOKS.get(attack_type.upper(), ["Investigate manually"])
    steps = [s.replace("{src_ip}", src_ip).replace("{dst_ip}", dst_ip) for s in steps]
    asyncio.create_task(_audit(auth.get("user_id",""), "remediation.view", attack_type))
    return {"attack_type": attack_type, "src_ip": src_ip, "steps": steps}


# ── GET /threats/intel/{ip} ───────────────────────────────────────────────────

@router.get("/intel/{ip}", summary="Multi-source threat intelligence for IP")
@limiter.limit("30/minute")
async def get_ip_intel(
    request:     Request,
    ip:          str,
    include_geo: bool = Query(True),
    include_risk: bool = Query(True),
    user = Depends(api_key_auth),
) -> Dict[str, Any]:
    auth = request.state.auth
    intel, geo = await asyncio.gather(
        _threat_intel.get_intel(ip),
        enrich_geo(ip) if include_geo else asyncio.sleep(0, result=None),
    )
    result: Dict[str, Any] = {"ip": _mask_ip(ip, auth.get("is_admin",False)), "intel": intel}
    if geo: result["geo"] = geo
    if include_risk:
        result["risk"] = _risk_engine.compute(
            intel.get("abuse_score",0)/100, ip, "", intel, []
        )
    asyncio.create_task(_audit(auth.get("user_id",""), "intel.lookup", ip,
                                request.client.host if request.client else ""))
    return result


# ── GET /threats/risk/{src_ip} ────────────────────────────────────────────────

@router.get("/risk/{src_ip}", summary="Composite risk score for an IP")
async def get_risk_score(
    request: Request,
    src_ip:  str,
    dst_ip:  str = Query(""),
    attack_types: List[str] = Query(default=[]),
    ml_score: float = Query(default=0.5, ge=0, le=1),
    user = Depends(api_key_auth),
) -> Dict[str, Any]:
    auth  = request.state.auth
    intel = await _threat_intel.get_intel(src_ip)
    risk  = _risk_engine.compute(ml_score, src_ip, dst_ip, intel, attack_types)
    return {"src_ip": _mask_ip(src_ip, auth.get("is_admin",False)),
            "dst_ip": dst_ip, "risk": risk}


# ── GET /threats/trajectory ───────────────────────────────────────────────────

@router.get("/trajectory", summary="Threat trajectory prediction")
async def get_trajectory(
    request:      Request,
    src_ip:       str,
    attack_types: List[str] = Query(default=[]),
    network_ips:  List[str] = Query(default=[]),
    user = Depends(api_key_auth),
) -> Dict[str, Any]:
    """Predicts where this attacker will move next (MITRE kill-chain transitions)."""
    try:
        async with httpx.AsyncClient(timeout=3.) as c:
            r = await c.post(f"{settings.ML_URL}/trajectory",
                             json={"attack_types": attack_types, "src_ip": src_ip,
                                   "network_ips": network_ips})
            if r.status_code == 200:
                return r.json()
    except Exception: pass
    # Local fallback
    predictions = _trajectory_predictor.predict(attack_types, src_ip, network_ips)
    return {"src_ip": src_ip, "predictions": predictions, "model": "rule-based"}


# ── Digital twin endpoint ─────────────────────────────────────────────────────

@router.post("/simulate", summary="Digital twin attack simulation")
@limiter.limit("20/minute")
async def simulate_attack(
    request:    Request,
    attack_type: str     = Body(...),
    target_ip:  str     = Body(...),
    score:      float   = Body(default=0.8, ge=0, le=1),
    user = Depends(api_key_auth),
) -> Dict[str, Any]:
    """Simulates attack impact in the digital twin — time_to_impact, severity, countermeasures."""
    try:
        async with httpx.AsyncClient(timeout=5.) as c:
            r = await c.post(f"{settings.ML_URL}/digital_twin/simulate",
                             json={"attack_type": attack_type, "target_ip": target_ip,
                                   "anomaly_score": score})
            if r.status_code == 200:
                twin_sims_total.labels(severity=r.json().get("severity","unknown")).inc()
                return r.json()
    except Exception: pass
    # Fallback
    twin_sims_total.labels(severity="simulated").inc()
    return {
        "attack_type":     attack_type,
        "target_ip":       target_ip,
        "severity":        "high" if score > 0.8 else "medium",
        "time_to_impact_s": round(10 / (score + 0.1), 1),
        "impact":          f"Simulated impact of {attack_type} on {target_ip}",
        "countermeasures": _PLAYBOOKS.get(attack_type.upper(), ["Investigate manually"]),
        "degraded":        True,
    }


# ── Webhooks ──────────────────────────────────────────────────────────────────

@router.post("/webhooks", summary="Register alert webhook", status_code=201)
async def create_webhook(
    request: Request,
    body:    WebhookCreate,
    user = Depends(api_key_auth),
) -> Dict[str, str]:
    auth = request.state.auth
    wh_id = str(uuid.uuid4())
    await db.pg.execute(
        "INSERT INTO webhooks (id, user_id, org_id, url, secret_hash, min_score, "
        "attack_types, active, created_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,NOW())",
        wh_id, auth.get("user_id",""), auth.get("org_id","default"),
        body.url,
        hashlib.sha256(body.secret.encode()).hexdigest(),
        body.min_score,
        json.dumps(body.attack_types),
        body.active,
    )
    asyncio.create_task(_audit(auth.get("user_id",""), "webhook.create", body.url))
    return {"webhook_id": wh_id, "url": body.url, "active": str(body.active)}


@router.delete("/webhooks/{webhook_id}", summary="Delete webhook")
async def delete_webhook(request: Request, webhook_id: str,
                          user = Depends(api_key_auth)) -> Dict[str, str]:
    auth = request.state.auth
    await db.pg.execute("DELETE FROM webhooks WHERE id=$1 AND org_id=$2",
                        webhook_id, auth.get("org_id","default"))
    asyncio.create_task(_audit(auth.get("user_id",""), "webhook.delete", webhook_id))
    return {"deleted": webhook_id}


# ── Export ────────────────────────────────────────────────────────────────────

@router.post("/export/{fmt}", summary="Async export (CSV / JSON)")
@limiter.limit("10/minute")
async def export_threats(
    request: Request, fmt: str,
    background_tasks: BackgroundTasks,
    hours:     int   = Query(24, ge=1, le=168),
    min_score: float = Query(0.5, ge=0, le=1),
    user = Depends(api_key_auth),
) -> Dict[str, str]:
    if fmt not in ("csv","json"):
        raise problem(400,"Invalid Format",f"Supported: csv, json",request)
    exports_total.labels(format=fmt).inc()
    auth  = request.state.auth
    since = datetime.utcnow()-timedelta(hours=hours)
    rows  = await db.clickhouse_execute(
        "SELECT timestamp,src_ip,dst_ip,score,attack_types,is_critical FROM packets "
        "WHERE org_id=%(org_id)s AND timestamp>=%(since)s AND score>=%(min_score)s "
        "ORDER BY score DESC LIMIT 50000",
        {"org_id": auth.get("org_id","default"), "since": since, "min_score": min_score},
    )
    threats = [_row_to_threat(r, auth.get("is_admin",False)) for r in rows]
    task_id = str(uuid.uuid4())
    background_tasks.add_task(_bg_export, task_id, threats, fmt)
    asyncio.create_task(_audit(auth.get("user_id",""), f"export.{fmt}",
                                f"hours={hours}", request.client.host if request.client else ""))
    return {"task_id": task_id, "status": "processing",
            "poll_url": f"/threats/export/{task_id}/status"}


@router.get("/export/{task_id}/status")
async def export_status(task_id: str, user = Depends(api_key_auth)) -> Dict[str, str]:
    val = await db.redis.get(f"export:{task_id}:status")
    if not val: raise HTTPException(404,"Task not found or expired")
    return {"task_id": task_id, "status": val.decode()}


@router.get("/export/{task_id}/download")
async def export_download(task_id: str, user = Depends(api_key_auth)) -> StreamingResponse:
    content = await db.redis.get(f"export:{task_id}")
    if not content: raise HTTPException(404,"Export not ready or expired")
    cs = content.decode(); is_csv = cs.startswith("timestamp,")
    return StreamingResponse(
        iter([cs]),
        media_type="text/csv" if is_csv else "application/json",
        headers={"Content-Disposition": f'attachment; filename="threats_{task_id}.{"csv" if is_csv else "json"}"'},
    )


# ── Self-Healing (v7 integration) ─────────────────────────────────────────────

@router.get("/health/code-scan", summary="Trigger AI code vulnerability scan")
@limiter.limit("5/minute")
async def code_scan(request: Request, user = Depends(api_key_auth)) -> Dict[str, Any]:
    """Triggers the v7 SelfHealingEngine to scan the codebase for vulnerabilities."""
    auth = request.state.auth
    if "admin" not in auth.get("scopes", []):
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Admin scope required")
    try:
        async with httpx.AsyncClient(timeout=30.) as c:
            r = await c.post(f"{settings.ML_URL}/self_heal/scan")
            if r.status_code == 200:
                asyncio.create_task(_audit(auth.get("user_id",""), "code_scan", "repo",
                                           request.client.host if request.client else ""))
                return r.json()
    except Exception as e:
        logger.warning(f"Code scan ML unavailable: {e}")
    return {"vulnerabilities": [], "proposals": [], "degraded": True}


@router.post("/health/heal/{proposal_id}", summary="Approve AI healing proposal")
async def approve_heal(
    request:     Request,
    proposal_id: str,
    user = Depends(api_key_auth),
) -> Dict[str, str]:
    """Human approves an AI-generated fix. Applies the fix and optionally creates a PR."""
    auth = request.state.auth
    if "admin" not in auth.get("scopes", []):
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Admin scope required")
    try:
        async with httpx.AsyncClient(timeout=15.) as c:
            r = await c.post(f"{settings.ML_URL}/self_heal/approve/{proposal_id}")
            if r.status_code == 200:
                asyncio.create_task(_audit(auth.get("user_id",""), "heal.approve", proposal_id,
                                           request.client.host if request.client else ""))
                return r.json()
    except Exception as e:
        raise HTTPException(503, f"Heal service unavailable: {e}")
    raise HTTPException(404, f"Proposal {proposal_id} not found")


# ── Audit log ─────────────────────────────────────────────────────────────────

@router.get("/audit", summary="Audit trail (admin)")
@limiter.limit("20/minute")
async def get_audit_log(
    request: Request,
    hours:   int          = Query(24, ge=1, le=168),
    action:  Optional[str] = None,
    user = Depends(api_key_auth),
) -> Dict[str, Any]:
    auth = request.state.auth
    if "admin" not in auth.get("scopes", []):
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Admin scope required")
    since = datetime.now(timezone.utc)-timedelta(hours=hours)
    qp: List[Any] = [since]
    extra = ""; idx = 2
    if action:
        extra = f" AND action LIKE ${idx}"; qp.append(f"%{action}%"); idx += 1
    rows = await db.pg.fetch(
        f"SELECT user_id,action,resource,request_ip,created_at FROM audit_logs "
        f"WHERE created_at>=$1 {extra} ORDER BY created_at DESC LIMIT 500",
        *qp,
    )
    return {"period_hours": hours, "entries": [
        {"user_id": r["user_id"], "action": r["action"], "resource": r["resource"],
         "request_ip": r["request_ip"], "timestamp": r["created_at"].isoformat()}
        for r in rows
    ]}


# ── Redis → WebSocket bridge (background task) ────────────────────────────────

async def _redis_to_ws_bridge() -> None:
    try:
        pubsub = db.redis.pubsub()
        await pubsub.subscribe("threats:new")
        async for message in pubsub.listen():
            if message["type"] == "message":
                try: await _ws_threats.broadcast(json.loads(message["data"]))
                except Exception: pass
    except asyncio.CancelledError: pass
    except Exception as e: logger.error(f"Redis→WS bridge: {e}")