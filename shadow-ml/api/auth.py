"""
api/auth.py — SHADOW-ML Authentication v10.0

JWT-based authentication with:
  • HMAC-SHA256 token signing
  • Role-based access control (RBAC): admin, analyst, readonly, service
  • Token rotation and revocation
  • Rate-limited login (brute-force protection)
  • Audit logging of all auth events
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import time
from base64 import urlsafe_b64decode, urlsafe_b64encode
from typing import Any, Dict, List, Optional, Set

from fastapi import Depends, HTTPException
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

logger = logging.getLogger("shadow.api.auth")


def _ph(pw: str) -> str:
    return hashlib.sha256(pw.encode()).hexdigest()


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

JWT_SECRET = "shadow-ml-jwt-master-secret-change-in-production"  # load from secrets in prod
JWT_EXPIRY_HOURS = 6
ALGORITHM = "HS256"

ROLES = {
    "admin":    ["read", "write", "delete", "manage", "debug"],
    "analyst":  ["read", "write"],
    "readonly": ["read"],
    "service":  ["read", "write", "internal"],
}

# Hardcoded service accounts (replace with DB lookup in production)
SERVICE_ACCOUNTS: Dict[str, Dict[str, str]] = {
    "admin":   {"password_hash": _ph("shadow-admin-2024!"),   "role": "admin"},
    "analyst": {"password_hash": _ph("shadow-analyst-2024!"), "role": "analyst"},
    "svc":     {"password_hash": _ph("shadow-svc-token"),      "role": "service"},
}

# ---------------------------------------------------------------------------
# Token operations
# ---------------------------------------------------------------------------

def _b64_encode(data: bytes) -> str:
    return urlsafe_b64encode(data).rstrip(b"=").decode()


def _b64_decode(s: str) -> bytes:
    padding = 4 - len(s) % 4
    return urlsafe_b64decode(s + "=" * padding)


def _sign(header_payload: str) -> str:
    return _b64_encode(
        hmac.new(JWT_SECRET.encode(), header_payload.encode(), hashlib.sha256).digest()
    )


def create_token(username: str, role: str, extra: Optional[Dict] = None) -> str:
    """Create a signed JWT token."""
    header = _b64_encode(json.dumps({"alg": ALGORITHM, "typ": "JWT"}).encode())
    payload = {
        "sub": username,
        "role": role,
        "permissions": ROLES.get(role, []),
        "iat": int(time.time()),
        "exp": int(time.time()) + JWT_EXPIRY_HOURS * 3600,
        **(extra or {}),
    }
    payload_b64 = _b64_encode(json.dumps(payload).encode())
    sig = _sign(f"{header}.{payload_b64}")
    return f"{header}.{payload_b64}.{sig}"


def decode_token(token: str) -> Dict[str, Any]:
    """Decode and verify a JWT token. Raises ValueError on failure."""
    try:
        parts = token.split(".")
        if len(parts) != 3:
            raise ValueError("malformed token")
        header_b64, payload_b64, sig = parts
        expected_sig = _sign(f"{header_b64}.{payload_b64}")
        if not hmac.compare_digest(sig, expected_sig):
            raise ValueError("invalid signature")
        payload = json.loads(_b64_decode(payload_b64))
        if payload.get("exp", 0) < time.time():
            raise ValueError("token expired")
        return payload
    except (KeyError, json.JSONDecodeError, Exception) as exc:
        raise ValueError(f"token decode failed: {exc}") from exc


# ---------------------------------------------------------------------------
# Revocation registry
# ---------------------------------------------------------------------------

_REVOKED_TOKENS: Set[str] = set()


def revoke_token(token: str) -> None:
    _REVOKED_TOKENS.add(token)
    logger.info("Token revoked")


def is_revoked(token: str) -> bool:
    return token in _REVOKED_TOKENS


# ---------------------------------------------------------------------------
# Rate limiter (login brute-force protection)
# ---------------------------------------------------------------------------

class _LoginRateLimiter:
    def __init__(self, max_attempts: int = 5, window_sec: float = 60.0):
        self._max = max_attempts
        self._window = window_sec
        self._attempts: Dict[str, List[float]] = {}

    def check(self, identifier: str) -> bool:
        now = time.time()
        times = self._attempts.setdefault(identifier, [])
        times[:] = [t for t in times if now - t < self._window]
        if len(times) >= self._max:
            return False
        times.append(now)
        return True


_RATE_LIMITER = _LoginRateLimiter()

# ---------------------------------------------------------------------------
# FastAPI dependency
# ---------------------------------------------------------------------------

_bearer = HTTPBearer(auto_error=False)


async def verify_token(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(_bearer),
) -> Dict[str, Any]:
    """FastAPI dependency: verifies Bearer JWT and returns decoded payload."""
    if credentials is None:
        raise HTTPException(status_code=401, detail="Missing Authorization header")
    token = credentials.credentials
    if is_revoked(token):
        raise HTTPException(status_code=401, detail="Token revoked")
    try:
        payload = decode_token(token)
    except ValueError as exc:
        raise HTTPException(status_code=401, detail=str(exc)) from exc
    logger.debug("Auth OK: user=%s role=%s", payload.get("sub"), payload.get("role"))
    return payload


def require_permission(permission: str):
    """FastAPI dependency factory for permission checks."""
    async def _check(payload: Dict = Depends(verify_token)) -> Dict:
        if permission not in payload.get("permissions", []):
            raise HTTPException(status_code=403, detail=f"Permission '{permission}' required")
        return payload
    return _check


# ---------------------------------------------------------------------------
# Login helper (used by /auth/login endpoint)
# ---------------------------------------------------------------------------

def authenticate(username: str, password: str, client_ip: str = "") -> Optional[str]:
    """
    Verify credentials and return a signed JWT token, or None on failure.
    """
    identifier = f"{client_ip}:{username}"
    if not _RATE_LIMITER.check(identifier):
        logger.warning("Rate limit exceeded for %s", identifier)
        return None
    account = SERVICE_ACCOUNTS.get(username)
    if not account:
        logger.warning("Unknown user: %s", username)
        return None
    if not hmac.compare_digest(account["password_hash"], _ph(password)):
        logger.warning("Bad password for user: %s", username)
        return None
    token = create_token(username, account["role"])
    logger.info("Login OK: user=%s role=%s", username, account["role"])
    return token
