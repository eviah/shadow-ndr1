"""
api/canary_routes.py — honeypot endpoints.

These paths look attractive to automated scanners and manual pentesters.
Any hit triggers:
  • a CRITICAL audit log entry
  • a Kafka tripwire event (shadow.threats, source=self-honeypot)
  • a 24h IP block
  • optional Slack/Discord webhook alert

Responses are deliberately bland 404s so scanners don't learn anything.
"""

from __future__ import annotations

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

from core import audit_log
from core.ip_blocklist import get_blocklist


canary_router = APIRouter(include_in_schema=False)

# Paths that attackers typically probe
_CANARY_PATHS = [
    "/admin/debug",
    "/admin/config",
    "/internal/shell",
    "/internal/status",
    "/backup.zip",
    "/.env",
    "/.git/config",
    "/.git/HEAD",
    "/wp-admin",
    "/wp-login.php",
    "/phpmyadmin",
    "/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php",
    "/.aws/credentials",
    "/server-status",
    "/actuator/env",
    "/actuator/heapdump",
    "/api/v1/auth/bypass",
    "/debug/pprof",
    "/solr/admin",
]


def _trip(request: Request, path: str) -> JSONResponse:
    ip = request.client.host if request.client else "unknown"
    audit_log.critical(
        "canary_hit",
        path=path,
        client_ip=ip,
        user_agent=request.headers.get("user-agent", ""),
        method=request.method,
    )
    get_blocklist().block(ip, ttl_seconds=86400, reason=f"canary_hit:{path}")
    return JSONResponse(status_code=404, content={"error": "not_found"})


def _make_handler(path: str):
    async def _h(request: Request):
        return _trip(request, path)
    return _h


for _p in _CANARY_PATHS:
    canary_router.add_api_route(
        _p,
        _make_handler(_p),
        methods=["GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH"],
        include_in_schema=False,
    )
