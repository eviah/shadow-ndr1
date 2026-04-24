# -*- coding: utf-8 -*-
"""
╔═══════════════════════════════════════════════════════════════════════════╗
║  Shadow NDR – Ultimate Asset Intelligence Engine                         ║
║  AI‑powered, real‑time asset discovery, classification, and risk         ║
╚═══════════════════════════════════════════════════════════════════════════╝
"""

import json
import time
from datetime import datetime, timedelta
from typing import Optional, List, Dict, Any
from enum import Enum

import httpx
from fastapi import APIRouter, Depends, Query, HTTPException, status, Request
from loguru import logger
from prometheus_client import Histogram, Counter
from slowapi import Limiter
from slowapi.util import get_remote_address

from ..db import db
from ..config import get_settings
from .auth import get_current_user

# =============================================================================
# Rate limiting
# =============================================================================
limiter = Limiter(key_func=get_remote_address)

router = APIRouter(prefix="/assets", tags=["Assets"])
settings = get_settings()

# =============================================================================
# Prometheus metrics
# =============================================================================
assets_query_duration = Histogram(
    "assets_query_duration_seconds",
    "Duration of assets API queries",
    ["operation"],
)
assets_errors_total = Counter(
    "assets_errors_total",
    "Total errors in assets API",
    ["operation"],
)
assets_cache_hits = Counter(
    "assets_cache_hits_total",
    "Cache hits for assets queries",
)
assets_cache_misses = Counter(
    "assets_cache_misses_total",
    "Cache misses for assets queries",
)

# =============================================================================
# Cache helper (Redis)
# =============================================================================
async def _get_cached(key: str) -> Optional[Any]:
    """Get value from Redis cache."""
    try:
        val = await db.redis_get(key)
        if val:
            assets_cache_hits.inc()
            return json.loads(val)
    except Exception:
        pass
    assets_cache_misses.inc()
    return None

async def _set_cache(key: str, value: Any, ttl: int = 60):
    """Store value in Redis cache."""
    try:
        await db.redis_set(key, json.dumps(value, default=str), ttl)
    except Exception:
        pass

# =============================================================================
# Helper: asset enrichment
# =============================================================================
async def enrich_asset(asset: Dict[str, Any]) -> Dict[str, Any]:
    """Add threat intelligence, geolocation, vulnerabilities."""
    ip = asset["ip"]
    # Geolocation (mock)
    geo = {
        "country": "Unknown",
        "city": "Unknown",
        "latitude": 0,
        "longitude": 0,
    }
    if ip.startswith("192.168."):
        geo["country"] = "Private Network"
    elif ip.startswith("10."):
        geo["country"] = "Private Network"
    elif ip.startswith("185.220."):
        geo["country"] = "Germany"
        geo["city"] = "Berlin"
    # Threat intelligence (mock)
    threat = {
        "abuse_score": 75 if ip.startswith("185.") else 0,
        "is_tor": ip.startswith("185.220."),
        "is_vpn": False,
        "asn": "AS12345",
    }
    # Vulnerabilities based on OS guess and open ports (mock)
    vulnerabilities = []
    if asset.get("os_guess"):
        # Simulate known vulnerabilities
        if "Windows" in asset["os_guess"]:
            vulnerabilities.append("CVE-2021-34527 (PrintNightmare)")
        if "Linux" in asset["os_guess"]:
            vulnerabilities.append("CVE-2021-3156 (sudo)")
    for port in asset.get("open_ports", []):
        if port == 22:
            vulnerabilities.append("CVE-2021-36368 (OpenSSH)")
        if port == 80:
            vulnerabilities.append("CVE-2021-41773 (Apache Path Traversal)")
    asset["enrichment"] = {
        "geo": geo,
        "threat_intel": threat,
        "vulnerabilities": vulnerabilities[:5],
    }
    return asset

# =============================================================================
# Helper: get asset risk score from ML service
# =============================================================================
async def get_asset_risk(ip: str, org_id: str) -> float:
    """Query ML service for asset risk score (0-1)."""
    # We'll use a simple fallback based on recent packet data.
    # In production, ML service would provide a model per asset.
    # For demo, we query ClickHouse for recent anomaly score average.
    try:
        rows = await db.clickhouse_execute(
            """
            SELECT AVG(score) FROM packets
            WHERE src_ip = %(ip)s AND org_id = %(org_id)s
              AND timestamp > now() - INTERVAL 1 HOUR
            """,
            {"ip": ip, "org_id": org_id}
        )
        avg_score = rows[0][0] if rows and rows[0][0] is not None else 0.0
        return float(avg_score)
    except Exception:
        return 0.0

# =============================================================================
# Endpoints
# =============================================================================

class AssetType(str, Enum):
    AIRCRAFT = "aircraft"
    AIRPORT  = "airport"
    ATC      = "atc"          # air-traffic-control equipment
    RADAR    = "radar"
    SWITCH   = "switch"
    UNKNOWN  = "unknown"

@router.get("")
@limiter.limit("100/minute")
async def get_assets(
    request: Request,
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    asset_type: Optional[AssetType] = None,
    icao24: Optional[str] = None,
    min_risk: Optional[float] = Query(None, ge=0, le=1),
    last_seen_after: Optional[datetime] = None,
    sort_by: str = Query("last_seen", regex="^(last_seen|risk|ip)$"),
    sort_order: str = Query("desc", regex="^(asc|desc)$"),
    user = Depends(get_current_user),
) -> Dict[str, Any]:
    """
    Get list of aviation assets (aircraft, airports, ATC, radar) with
    filtering, sorting, and AI enrichment.
    """
    start_time = time.time()
    try:
        org_id = user["org_id"]

        # The underlying table still carries legacy `is_train` / `train_id` columns
        # for back-compat; we surface them as `is_aircraft` / `icao24` at the API.
        query = """
            SELECT ip, hostname, os_guess, open_ports, first_seen, last_seen,
                   is_train AS is_aircraft, train_id AS icao24
            FROM assets
            WHERE org_id = $1
        """
        params = [org_id]
        param_idx = 2

        if asset_type:
            if asset_type == AssetType.AIRCRAFT:
                query += " AND is_train = true"
            elif asset_type == AssetType.ATC:
                query += " AND (open_ports @> ARRAY[2404, 502] OR os_guess ILIKE '%atc%')"
            elif asset_type == AssetType.SWITCH:
                query += " AND (open_ports @> ARRAY[20000, 20004] OR os_guess ILIKE '%switch%')"
            elif asset_type == AssetType.RADAR:
                query += " AND (open_ports @> ARRAY[502, 2404] OR os_guess ILIKE '%radar%')"

        if icao24:
            query += f" AND train_id = ${param_idx}"
            params.append(icao24)
            param_idx += 1

        if last_seen_after:
            query += f" AND last_seen >= ${param_idx}"
            params.append(last_seen_after)
            param_idx += 1

        # Sorting
        order = "DESC" if sort_order == "desc" else "ASC"
        if sort_by == "risk":
            # Risk will be computed after; we'll sort in memory
            pass
        else:
            query += f" ORDER BY {sort_by} {order}"

        query += f" LIMIT ${param_idx} OFFSET ${param_idx+1}"
        params.append(limit)
        params.append(offset)

        async with db.pg.acquire() as conn:
            rows = await conn.fetch(query, *params)

        # Build asset list
        assets = []
        for row in rows:
            asset = {
                "ip": row["ip"],
                "hostname": row["hostname"],
                "os_guess": row["os_guess"],
                "open_ports": row["open_ports"] if isinstance(row["open_ports"], list) else [],
                "first_seen": row["first_seen"].isoformat() if row["first_seen"] else None,
                "last_seen": row["last_seen"].isoformat() if row["last_seen"] else None,
                "is_aircraft": row["is_aircraft"],
                "icao24": row["icao24"],
            }

            # Get risk score
            risk = await get_asset_risk(asset["ip"], org_id)
            asset["risk_score"] = risk

            # Enrich with AI classification
            if asset_type is None:
                # Auto-classify if not specified
                if asset["is_aircraft"]:
                    asset["asset_type"] = "aircraft"
                elif 2404 in asset["open_ports"] or 502 in asset["open_ports"]:
                    asset["asset_type"] = "atc"
                elif 20000 in asset["open_ports"] or 20004 in asset["open_ports"]:
                    asset["asset_type"] = "switch"
                else:
                    asset["asset_type"] = "unknown"
            else:
                asset["asset_type"] = asset_type.value

            # Filter by min_risk after computing
            if min_risk is not None and risk < min_risk:
                continue

            assets.append(asset)

        # If sorting by risk, sort in memory
        if sort_by == "risk":
            assets.sort(key=lambda a: a["risk_score"], reverse=(sort_order == "desc"))

        # Apply limit/offset again (since we may have filtered)
        total_count = len(assets)
        assets = assets[offset:offset+limit]

        # Enrich each asset (add threat intel, vulnerabilities, geo)
        for i, asset in enumerate(assets):
            assets[i] = await enrich_asset(asset)

        # Cache result (short TTL)
        cache_key = f"assets:{org_id}:{limit}:{offset}:{asset_type}:{icao24}:{min_risk}:{last_seen_after}:{sort_by}:{sort_order}"
        await _set_cache(cache_key, {"total": total_count, "assets": assets}, ttl=10)

        return {
            "total": total_count,
            "limit": limit,
            "offset": offset,
            "assets": assets,
        }

    except Exception as e:
        assets_errors_total.labels(operation="list").inc()
        logger.error(f"Assets list error: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")
    finally:
        duration = time.time() - start_time
        assets_query_duration.labels(operation="list").observe(duration)

@router.get("/{ip}")
@limiter.limit("60/minute")
async def get_asset(
    request: Request,
    ip: str,
    include_history: bool = Query(False, description="Include risk history (time series)"),
    user = Depends(get_current_user),
) -> Dict[str, Any]:
    """
    Get detailed asset information, including risk score, enrichment, and optional history.
    """
    start_time = time.time()
    try:
        org_id = user["org_id"]
        async with db.pg.acquire() as conn:
            row = await conn.fetchrow(
                """
                SELECT ip, hostname, os_guess, open_ports, first_seen, last_seen,
                       is_train AS is_aircraft, train_id AS icao24
                FROM assets
                WHERE ip = $1 AND org_id = $2
                """,
                ip, org_id
            )

        if not row:
            raise HTTPException(status_code=404, detail="Asset not found")

        asset = {
            "ip": row["ip"],
            "hostname": row["hostname"],
            "os_guess": row["os_guess"],
            "open_ports": row["open_ports"] if isinstance(row["open_ports"], list) else [],
            "first_seen": row["first_seen"].isoformat() if row["first_seen"] else None,
            "last_seen": row["last_seen"].isoformat() if row["last_seen"] else None,
            "is_aircraft": row["is_aircraft"],
            "icao24": row["icao24"],
        }

        # Risk score
        risk = await get_asset_risk(ip, org_id)
        asset["risk_score"] = risk

        # Auto-classify
        if asset["is_aircraft"]:
            asset["asset_type"] = "aircraft"
        elif 2404 in asset["open_ports"] or 502 in asset["open_ports"]:
            asset["asset_type"] = "atc"
        elif 20000 in asset["open_ports"] or 20004 in asset["open_ports"]:
            asset["asset_type"] = "switch"
        else:
            asset["asset_type"] = "unknown"

        # Enrich with threat intel, geo, vulns
        asset = await enrich_asset(asset)

        # Include risk history if requested
        if include_history:
            # Query ClickHouse for risk over last 24 hours (one point per hour)
            rows = await db.clickhouse_execute(
                """
                SELECT
                    toStartOfHour(timestamp) AS hour,
                    AVG(score) AS avg_score
                FROM packets
                WHERE src_ip = %(ip)s AND org_id = %(org_id)s
                  AND timestamp > now() - INTERVAL 1 DAY
                GROUP BY hour
                ORDER BY hour
                """,
                {"ip": ip, "org_id": org_id}
            )
            asset["risk_history"] = [
                {"timestamp": row[0].isoformat(), "score": float(row[1])}
                for row in rows
            ]

        return asset

    except HTTPException:
        raise
    except Exception as e:
        assets_errors_total.labels(operation="detail").inc()
        logger.error(f"Asset detail error for {ip}: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")
    finally:
        duration = time.time() - start_time
        assets_query_duration.labels(operation="detail").observe(duration)

@router.get("/{ip}/risk-history")
@limiter.limit("60/minute")
async def get_asset_risk_history(
    request: Request,
    ip: str,
    hours: int = Query(24, ge=1, le=168),
    user = Depends(get_current_user),
) -> Dict[str, Any]:
    """
    Get risk score time series for an asset.
    """
    start_time = time.time()
    try:
        org_id = user["org_id"]
        rows = await db.clickhouse_execute(
            """
            SELECT
                toStartOfHour(timestamp) AS hour,
                AVG(score) AS avg_score,
                MAX(score) AS max_score,
                COUNT(*) AS packet_count
            FROM packets
            WHERE src_ip = %(ip)s AND org_id = %(org_id)s
              AND timestamp > now() - INTERVAL %(hours)s HOUR
            GROUP BY hour
            ORDER BY hour
            """,
            {"ip": ip, "org_id": org_id, "hours": hours}
        )
        history = [
            {
                "timestamp": row[0].isoformat(),
                "avg_score": float(row[1]),
                "max_score": float(row[2]),
                "packet_count": row[3],
            }
            for row in rows
        ]
        return {"ip": ip, "hours": hours, "history": history}
    except Exception as e:
        logger.error(f"Risk history error: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")
    finally:
        duration = time.time() - start_time
        assets_query_duration.labels(operation="history").observe(duration)