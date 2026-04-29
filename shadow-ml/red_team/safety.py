"""
Safety guard — the ONLY file that decides where traffic is allowed to go.

This is deliberately its own module so tampering with it is conspicuous
(git blame, code review). Every outbound call in the red-team harness
routes through `enforce()`. If you see an HTTP/socket call that bypasses
this check, that is a bug.
"""

from __future__ import annotations

import ipaddress
import os
import socket
from dataclasses import dataclass
from typing import Set
from urllib.parse import urlparse


# Hosts allowed — localhost only. Environment override requires an
# explicit opt-in flag AND still goes through IP resolution.
_DEFAULT_HOSTS: Set[str] = {
    "localhost", "127.0.0.1", "::1", "0.0.0.0",
    # Docker default bridge gateway + common compose service names
    "host.docker.internal",
    "shadow-ml", "shadow-backend", "shadow-postgres",
    "shadow-kafka", "shadow-redis", "shadow-ingestion",
}

# Allowed port range — Shadow NDR's own service band
_ALLOWED_PORTS = {
    3000, 3001, 3002,      # MT frontend + backend + alt
    8000, 8001, 8080,      # shadow-ml FastAPI
    5432, 5433,            # postgres
    6379,                  # redis
    9092, 9093,            # kafka
    9000,                  # clickhouse
}


class TargetBlocked(Exception):
    """Raised when a target fails the allowlist check. Do NOT catch globally."""


@dataclass(frozen=True)
class Target:
    scheme: str
    host: str
    port: int
    raw: str


def _resolve_local(host: str) -> bool:
    """Return True iff host resolves to a loopback / private RFC1918 address."""
    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror:
        return False
    for _, _, _, _, sockaddr in infos:
        ip_str = sockaddr[0]
        try:
            ip = ipaddress.ip_address(ip_str)
        except ValueError:
            continue
        if ip.is_loopback:
            return True
        if ip.is_private:
            # Private networks are allowed only when env opt-in is set.
            if os.environ.get("RED_TEAM_ALLOW_PRIVATE_LAN") == "i-own-this":
                return True
    return False


def enforce(url: str) -> Target:
    """
    Validate that `url` points at a service the harness is allowed to touch.
    Raises TargetBlocked on any other target. Call this BEFORE every request.
    """
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https", "ws", "wss", "tcp"):
        raise TargetBlocked(f"scheme not allowed: {parsed.scheme}")
    host = (parsed.hostname or "").lower()
    if not host:
        raise TargetBlocked(f"no host in url: {url}")

    port = parsed.port
    if port is None:
        port = {"http": 80, "https": 443, "ws": 80, "wss": 443}.get(parsed.scheme, 0)

    # Hostname allowlist OR local-IP resolution
    if host not in _DEFAULT_HOSTS and not _resolve_local(host):
        raise TargetBlocked(
            f"target '{host}' is not on the localhost allowlist. "
            f"This harness only attacks your own machine."
        )

    if port and port not in _ALLOWED_PORTS:
        # Allow any port when the host is strictly loopback literal,
        # since dev rebinding is common.
        if host not in ("localhost", "127.0.0.1", "::1"):
            raise TargetBlocked(f"port {port} not in allowed band")

    return Target(scheme=parsed.scheme, host=host, port=port, raw=url)


def bulk_enforce(urls: list[str]) -> list[Target]:
    return [enforce(u) for u in urls]
