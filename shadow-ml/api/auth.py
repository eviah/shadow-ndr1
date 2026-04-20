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
import os
import time
from base64 import urlsafe_b64decode, urlsafe_b64encode
from typing import Any, Dict, List, Optional, Set

from fastapi import Depends, HTTPException, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

logger = logging.getLogger("shadow.api.auth")


def _ph(pw: str) -> str:
    return hashlib.sha256(pw.encode()).hexdigest()


# ---------------------------------------------------------------------------
# Configuration (loaded from env / secret vault; fails closed)
# ---------------------------------------------------------------------------


def _load_jwt_secret() -> str:
    val = os.environ.get("SHADOW_ML_JWT_SECRET", "").strip()
    if val:
        return val
    # fall back to in-process vault (ephemeral, rotates per process)
    try:
        from core.secrets import get_secret
        v = get_secret("JWT_SECRET")
        if v:
            return v
    except Exception:
        pass
    # Last resort: generate ephemeral — WARN LOUDLY.
    import secrets as _s
    ephemeral = _s.token_hex(32)
    logger.warning("SHADOW_ML_JWT_SECRET not set; using ephemeral secret (tokens invalidated on restart)")
    return ephemeral


JWT_SECRET = _load_jwt_secret()
JWT_EXPIRY_HOURS = int(os.environ.get("SHADOW_ML_JWT_EXPIRY_HOURS", "6"))
ALGORITHM = "HS256"
JWT_ISSUER = "shadow-ml"

ROLES = {
    "admin":    ["read", "write", "delete", "manage", "debug"],
    "analyst":  ["read", "write"],
    "readonly": ["read"],
    "service":  ["read", "write", "internal"],
}

# Service accounts. Passwords are ONLY used for /auth/login; preferred auth
# for machine-to-machine is X-API-Key (sha256-hashed, loaded from env).
def _load_service_accounts() -> Dict[str, Dict[str, str]]:
    # Admin password can be overridden via env; otherwise ephemeral strong one.
    import secrets as _s
    env_admin = os.environ.get("SHADOW_ML_ADMIN_PASSWORD", "").strip()
    admin_pw = env_admin or _s.token_urlsafe(24)
    if not env_admin:
        logger.warning("SHADOW_ML_ADMIN_PASSWORD not set; using ephemeral admin password: %s", admin_pw)
    env_analyst = os.environ.get("SHADOW_ML_ANALYST_PASSWORD", "").strip() or _s.token_urlsafe(24)
    return {
        "admin":   {"password_hash": _ph(admin_pw),     "role": "admin"},
        "analyst": {"password_hash": _ph(env_analyst),  "role": "analyst"},
    }


SERVICE_ACCOUNTS: Dict[str, Dict[str, str]] = _load_service_accounts()


# ---------------------------------------------------------------------------
# API key support: env contains comma-separated sha256 hex digests.
# Caller sends plaintext in X-API-Key; we sha256 and compare in constant time.
# ---------------------------------------------------------------------------

def _load_api_key_hashes() -> Set[str]:
    raw = os.environ.get("SHADOW_ML_API_KEYS", "").strip()
    if not raw:
        return set()
    return {h.strip().lower() for h in raw.split(",") if h.strip()}


API_KEY_HASHES: Set[str] = _load_api_key_hashes()


def verify_api_key(plaintext: str) -> bool:
    if not plaintext or not API_KEY_HASHES:
        return False
    digest = hashlib.sha256(plaintext.encode()).hexdigest().lower()
    # constant-time any-match
    match = False
    for h in API_KEY_HASHES:
        if hmac.compare_digest(digest, h):
            match = True
    return match

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


def verify_auth_header(request: Request) -> Optional[Dict[str, Any]]:
    """
    Combined verifier used by ASGI-level auth middleware.
    Accepts either:
      - Authorization: Bearer <jwt>
      - X-API-Key: <plaintext>
    Returns payload dict on success, None on failure.
    Never raises.
    """
    # X-API-Key fast path
    api_key = request.headers.get("x-api-key", "").strip()
    if api_key and verify_api_key(api_key):
        return {"sub": "api-key", "role": "service", "permissions": ROLES["service"]}

    auth = request.headers.get("authorization", "")
    if not auth.lower().startswith("bearer "):
        return None
    token = auth.split(None, 1)[1].strip()
    if is_revoked(token):
        return None
    try:
        return decode_token(token)
    except ValueError:
        return None


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
