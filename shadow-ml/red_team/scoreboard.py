"""
Detection scoreboard — after a campaign runs, query the NDR's own threat /
alert log to figure out what your detectors actually caught.

Coverage = (techniques that produced ≥1 logged threat or alert)
         / (techniques fired)
"""

from __future__ import annotations

import logging
import time
from typing import Any, Dict, List, Set

import httpx

from .safety import enforce

logger = logging.getLogger("red_team.scoreboard")


async def _get(client: httpx.AsyncClient, url: str,
              token: str | None) -> List[dict]:
    enforce(url)
    hdrs = {"Authorization": f"Bearer {token}"} if token else {}
    try:
        r = await client.get(url, headers=hdrs, timeout=10.0)
        if r.status_code != 200:
            return []
        body = r.json()
        if isinstance(body, dict):
            for key in ("data", "threats", "alerts", "items", "results"):
                if key in body and isinstance(body[key], list):
                    return body[key]
            return []
        return body if isinstance(body, list) else []
    except (httpx.HTTPError, ValueError):
        return []


async def score_detection(campaign) -> Dict[str, Any]:
    """Query backend for threats/alerts created during the campaign window
    and compute per-technique detection coverage."""
    if not campaign.results:
        return {"coverage_pct": 0.0, "threats": 0, "alerts": 0}

    start_ts = min(r.ts for r in campaign.results) - 1.0
    end_ts = max(r.ts for r in campaign.results) + 60.0  # 60s detection lag

    # Wait briefly so async detectors can flush
    logger.info("waiting 5s for detector pipelines to settle...")
    import asyncio
    await asyncio.sleep(5.0)

    threats = await _get(campaign.client,
                        f"{campaign.backend}/api/threats?limit=2000",
                        campaign._token)
    alerts = await _get(campaign.client,
                       f"{campaign.backend}/api/alerts?limit=2000",
                       campaign._token)

    # Filter to campaign window
    def _ts(item: dict) -> float:
        for k in ("created_at", "createdAt", "timestamp", "ts", "first_seen"):
            v = item.get(k)
            if v is None:
                continue
            if isinstance(v, (int, float)):
                # ms vs s heuristic
                return v / 1000.0 if v > 1e12 else float(v)
            try:
                from datetime import datetime
                return datetime.fromisoformat(
                    str(v).replace("Z", "+00:00")
                ).timestamp()
            except (ValueError, TypeError):
                continue
        return 0.0

    threats_in_window = [t for t in threats
                        if start_ts <= _ts(t) <= end_ts]
    alerts_in_window = [a for a in alerts
                       if start_ts <= _ts(a) <= end_ts]

    # Fired techniques
    fired_techniques: Set[str] = {
        f"{r.technique}/{r.sub_technique}" for r in campaign.results
    }

    # Heuristic mapping: pull keywords from threat/alert titles+desc and try to
    # bucket them. NDR-specific tagging would be more accurate.
    detected_keywords: Set[str] = set()
    for item in threats_in_window + alerts_in_window:
        text = " ".join(str(item.get(k, "")) for k in
                       ("title", "name", "type", "description",
                        "message", "category", "rule", "kind")).lower()
        for kw in [
            "brute", "login", "auth", "jwt", "token", "refresh",
            "tenant", "isolation", "idor",
            "sqli", "injection", "traversal", "xss", "ssrf", "command",
            "rate", "flood", "spoof", "xff",
            "adsb", "icao", "gps", "kinematic", "altitude", "ghost",
            "modbus", "iec", "dnp3", "opcua", "industrial",
            "exfil", "export", "beacon", "c2", "evasion",
            "replay", "anomaly", "impersonation",
        ]:
            if kw in text:
                detected_keywords.add(kw)

    # Map sub-techniques to keywords for coverage scoring
    technique_to_keywords = {
        "auth/brute_force": {"brute", "login"},
        "auth/jwt_tamper": {"jwt", "token"},
        "auth/refresh_abuse": {"refresh", "token"},
        "auth/user_enum": {"login", "auth"},
        "tenant/idor_asset": {"tenant", "isolation", "idor"},
        "tenant/idor_threats": {"tenant", "isolation", "idor"},
        "injection/sqli_query": {"sqli", "injection"},
        "injection/path_traversal": {"traversal"},
        "injection/xss_body": {"xss"},
        "injection/xss_alert": {"xss"},
        "injection/ssrf": {"ssrf"},
        "injection/cmd_inject": {"command", "injection"},
        "injection/proto_pollute": {"injection"},
        "ratelimit/xff_spoof": {"rate", "spoof", "xff"},
        "ratelimit/login_burst": {"rate", "brute"},
        "adsb/kinematic_jump": {"kinematic", "adsb"},
        "adsb/icao_impersonation": {"icao", "impersonation"},
        "adsb/gps_jump": {"gps"},
        "adsb/alt_impossible": {"altitude", "kinematic"},
        "adsb/speed_impossible": {"kinematic"},
        "adsb/ghost_swarm": {"ghost", "spoof"},
        "adsb/replay": {"replay"},
        "industrial/modbus_fc_06": {"modbus", "industrial"},
        "industrial/modbus_fc_05": {"modbus", "industrial"},
        "industrial/iec104_apci_flood": {"iec", "flood"},
        "industrial/dnp3_unsol": {"dnp3", "industrial"},
        "industrial/opcua_oversize": {"opcua"},
        "lateral/threat_flood": {"flood", "anomaly"},
        "exfil/export_loop": {"exfil", "export"},
        "exfil/fast_poll": {"exfil"},
        "beacon/periodic_callback": {"beacon", "c2"},
        "evasion/slow_ua_fuzz": {"evasion"},
    }

    detected_techs: Set[str] = set()
    for tech in fired_techniques:
        kws = technique_to_keywords.get(tech, set())
        if kws & detected_keywords:
            detected_techs.add(tech)

    coverage = (
        100.0 * len(detected_techs) / max(len(fired_techniques), 1)
    )

    miss_list = sorted(fired_techniques - detected_techs)

    return {
        "threats": len(threats_in_window),
        "alerts": len(alerts_in_window),
        "fired_techniques": len(fired_techniques),
        "detected_techniques": len(detected_techs),
        "coverage_pct": round(coverage, 1),
        "detected_keywords": sorted(detected_keywords),
        "missed_techniques": miss_list,
        "window": {"start": start_ts, "end": end_ts},
    }
