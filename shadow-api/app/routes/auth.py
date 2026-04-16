# -*- coding: utf-8 -*-
"""
╔═══════════════════════════════════════════════════════════════════════════╗
║  Shadow NDR – Ultimate Authentication Layer                              ║
║  AI‑ready, multi‑tenant, production‑grade auth for railway security     ║
╚═══════════════════════════════════════════════════════════════════════════╝
"""

import hashlib
import secrets
import time
from datetime import datetime, timedelta
from typing import Optional, Dict, Any, List

import jwt
from fastapi import APIRouter, Depends, HTTPException, status, Request, Response, BackgroundTasks
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from loguru import logger
from passlib.context import CryptContext
from pydantic import BaseModel, EmailStr, Field
from slowapi import Limiter
from slowapi.util import get_remote_address

from ..config import get_settings
from ..db import db

# =============================================================================
# Rate limiting (protects against brute‑force)
# =============================================================================
limiter = Limiter(key_func=get_remote_address)

router = APIRouter(prefix="/auth", tags=["Authentication"])
settings = get_settings()
security = HTTPBearer(auto_error=False)
pwd_context = CryptContext(schemes=["argon2", "bcrypt"], deprecated="auto")

# =============================================================================
# Pydantic models
# =============================================================================

class UserCreate(BaseModel):
    username: str = Field(..., min_length=3, max_length=50)
    email: EmailStr
    password: str = Field(..., min_length=8)
    role: str = "viewer"           # admin, analyst, viewer
    org_id: Optional[str] = None   # if None, uses default

class UserResponse(BaseModel):
    id: str
    username: str
    email: str
    role: str
    org_id: str
    created_at: datetime
    is_active: bool

class LoginRequest(BaseModel):
    username: str
    password: str

class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int

class RefreshRequest(BaseModel):
    refresh_token: str

class ChangePasswordRequest(BaseModel):
    old_password: str
    new_password: str = Field(..., min_length=8)

class ResetPasswordRequest(BaseModel):
    email: EmailStr

class ResetPasswordConfirm(BaseModel):
    token: str
    new_password: str = Field(..., min_length=8)

# =============================================================================
# Helper functions
# =============================================================================

def create_access_token(data: Dict[str, Any], expires_delta: Optional[timedelta] = None) -> str:
    """Create a short‑lived access token."""
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=settings.auth.access_token_expire_minutes))
    to_encode.update({"exp": expire, "type": "access"})
    return jwt.encode(to_encode, settings.auth.secret_key.get_secret_value(), algorithm=settings.auth.algorithm)

def create_refresh_token(data: Dict[str, Any]) -> str:
    """Create a long‑lived refresh token."""
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(days=settings.auth.refresh_token_expire_days)
    to_encode.update({"exp": expire, "type": "refresh"})
    return jwt.encode(to_encode, settings.auth.secret_key.get_secret_value(), algorithm=settings.auth.algorithm)

async def get_user_by_username(username: str) -> Optional[Dict[str, Any]]:
    """Fetch user from PostgreSQL by username."""
    async with db.acquire() as conn:
        row = await conn.fetchrow(
            "SELECT id, username, email, hashed_password, role, org_id, created_at, is_active "
            "FROM users WHERE username = $1",
            username
        )
        if row:
            return dict(row)
    return None

async def get_user_by_email(email: str) -> Optional[Dict[str, Any]]:
    async with db.acquire() as conn:
        row = await conn.fetchrow(
            "SELECT id, username, email, hashed_password, role, org_id, created_at, is_active "
            "FROM users WHERE email = $1",
            email
        )
        if row:
            return dict(row)
    return None

async def create_user(user_data: UserCreate) -> Dict[str, Any]:
    """Insert a new user into the database."""
    hashed = pwd_context.hash(user_data.password)
    org_id = user_data.org_id or "default"
    async with db.acquire() as conn:
        row = await conn.fetchrow(
            """
            INSERT INTO users (username, email, hashed_password, role, org_id)
            VALUES ($1, $2, $3, $4, $5)
            RETURNING id, username, email, role, org_id, created_at, is_active
            """,
            user_data.username, user_data.email, hashed, user_data.role, org_id
        )
        return dict(row)

async def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)

async def log_auth_attempt(username: str, success: bool, ip: str, user_agent: str):
    """Log authentication attempt (can be extended to send alerts)."""
    level = "INFO" if success else "WARNING"
    logger.log(level, f"Auth attempt: user={username}, success={success}, ip={ip}, ua={user_agent}")
    # Optional: store in DB for audit
    async with db.acquire() as conn:
        await conn.execute(
            "INSERT INTO auth_logs (username, success, ip, user_agent) VALUES ($1, $2, $3, $4)",
            username, success, ip, user_agent
        )

# =============================================================================
# Routes
# =============================================================================

@router.post("/register", response_model=UserResponse)
@limiter.limit("5/minute")  # limit registration attempts
async def register(request: Request, user_data: UserCreate, background_tasks: BackgroundTasks):
    """Create a new user account."""
    # Check if user already exists
    existing = await get_user_by_username(user_data.username)
    if existing:
        raise HTTPException(status_code=400, detail="Username already taken")
    existing_email = await get_user_by_email(user_data.email)
    if existing_email:
        raise HTTPException(status_code=400, detail="Email already registered")

    # Create user
    new_user = await create_user(user_data)

    # Optional: send welcome email (background task)
    background_tasks.add_task(send_welcome_email, new_user["email"], new_user["username"])

    return new_user

@router.post("/login")
@limiter.limit("10/minute")
async def login(request: Request, response: Response, login_data: LoginRequest):
    """Authenticate user and set Secure HttpOnly cookies."""
    ip = request.client.host
    ua = request.headers.get("user-agent", "")
    user = await get_user_by_username(login_data.username)
    if not user:
        await log_auth_attempt(login_data.username, False, ip, ua)
        raise HTTPException(status_code=401, detail="Invalid credentials")

    if not user["is_active"]:
        await log_auth_attempt(login_data.username, False, ip, ua)
        raise HTTPException(status_code=401, detail="Account disabled")

    if not await verify_password(login_data.password, user["hashed_password"]):
        await log_auth_attempt(login_data.username, False, ip, ua)
        raise HTTPException(status_code=401, detail="Invalid credentials")

    # Success
    await log_auth_attempt(login_data.username, True, ip, ua)

    token_data = {
        "sub": user["username"],
        "user_id": user["id"],
        "role": user["role"],
        "org_id": user["org_id"],
    }
    access_token = create_access_token(token_data)
    refresh_token = create_refresh_token(token_data)

    is_secure = not settings.is_development
    response.set_cookie(
        key="access_token",
        value=access_token,
        httponly=True,
        secure=is_secure,
        samesite="strict",
        max_age=settings.auth.access_token_expire_minutes * 60,
    )
    response.set_cookie(
        key="refresh_token",
        value=refresh_token,
        httponly=True,
        secure=is_secure,
        samesite="strict",
        max_age=settings.auth.refresh_token_expire_days * 24 * 60 * 60,
    )

    return {"message": "Login successful", "access_token": access_token}

@router.post("/refresh")
async def refresh(request: Request, response: Response, body: Optional[RefreshRequest] = None):
    """Get a new access token using a valid refresh token from cookies."""
    refresh_token = request.cookies.get("refresh_token")
    if not refresh_token and body:
        refresh_token = body.refresh_token
    if not refresh_token:
        raise HTTPException(status_code=401, detail="Refresh token missing")
        
    try:
        payload = jwt.decode(
            refresh_token,
            settings.auth.secret_key.get_secret_value(),
            algorithms=[settings.auth.algorithm]
        )
        if payload.get("type") != "refresh":
            raise jwt.PyJWTError
            
        token_data = {
            "sub": payload["sub"],
            "user_id": payload["user_id"],
            "role": payload["role"],
            "org_id": payload["org_id"],
        }
        new_access = create_access_token(token_data)
        
        response.set_cookie(
            key="access_token",
            value=new_access,
            httponly=True,
            secure=not settings.is_development,
            samesite="strict",
            max_age=settings.auth.access_token_expire_minutes * 60,
        )
        return {"message": "Token refreshed"}
    except jwt.PyJWTError:
        raise HTTPException(status_code=401, detail="Invalid refresh token")

@router.post("/logout")
async def logout(response: Response, credentials: Optional[HTTPAuthorizationCredentials] = Depends(security)):
    """Logout (clears cookies)."""
    response.delete_cookie("access_token")
    response.delete_cookie("refresh_token")
    return {"message": "Logged out"}

@router.post("/change-password")
async def change_password(
    request: ChangePasswordRequest,
    current_user: Dict = Depends(get_current_user),
):
    """Change password for authenticated user."""
    user = await get_user_by_username(current_user["username"])
    if not user or not await verify_password(request.old_password, user["hashed_password"]):
        raise HTTPException(status_code=400, detail="Current password incorrect")

    new_hashed = pwd_context.hash(request.new_password)
    async with db.acquire() as conn:
        await conn.execute(
            "UPDATE users SET hashed_password = $1 WHERE id = $2",
            new_hashed, user["id"]
        )
    return {"message": "Password changed successfully"}

@router.post("/reset-password-request")
@limiter.limit("3/hour")
async def reset_password_request(request: ResetPasswordRequest, background_tasks: BackgroundTasks):
    """Send password reset email (placeholder)."""
    user = await get_user_by_email(request.email)
    if not user:
        # Do not reveal whether email exists for security
        return {"message": "If the email exists, a reset link has been sent"}

    # Generate secure reset token (store in DB with expiry)
    reset_token = secrets.token_urlsafe(32)
    expiry = datetime.utcnow() + timedelta(hours=1)
    async with db.acquire() as conn:
        await conn.execute(
            "INSERT INTO password_resets (user_id, token, expires_at) VALUES ($1, $2, $3)",
            user["id"], reset_token, expiry
        )

    # Send email (background task)
    background_tasks.add_task(send_reset_email, user["email"], reset_token)

    return {"message": "If the email exists, a reset link has been sent"}

@router.post("/reset-password")
async def reset_password_confirm(request: ResetPasswordConfirm):
    """Reset password using token."""
    async with db.acquire() as conn:
        row = await conn.fetchrow(
            "SELECT user_id, expires_at FROM password_resets WHERE token = $1",
            request.token
        )
        if not row:
            raise HTTPException(status_code=400, detail="Invalid or expired token")
        if row["expires_at"] < datetime.utcnow():
            raise HTTPException(status_code=400, detail="Token expired")

        new_hashed = pwd_context.hash(request.new_password)
        await conn.execute(
            "UPDATE users SET hashed_password = $1 WHERE id = $2",
            new_hashed, row["user_id"]
        )
        await conn.execute("DELETE FROM password_resets WHERE token = $1", request.token)

    return {"message": "Password reset successfully"}

@router.get("/me", response_model=UserResponse)
async def get_me(current_user: Dict = Depends(get_current_user)):
    """Get current user profile."""
    user = await get_user_by_username(current_user["username"])
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return user

# =============================================================================
# Dependency for token validation (used by other routes)
# =============================================================================

async def get_current_user(request: Request, credentials: Optional[HTTPAuthorizationCredentials] = Depends(security)) -> Dict[str, Any]:
    """Validate access token from cookie (fallback to Bearer) and return user info."""
    token = request.cookies.get("access_token")
    if not token and credentials:
        token = credentials.credentials
        
    if not token:
        raise HTTPException(status_code=401, detail="Not authenticated")
        
    try:
        payload = jwt.decode(
            token,
            settings.auth.secret_key.get_secret_value(),
            algorithms=[settings.auth.algorithm]
        )
        if payload.get("type") != "access":
            raise jwt.PyJWTError
        return {
            "username": payload.get("sub"),
            "user_id": payload.get("user_id"),
            "role": payload.get("role"),
            "org_id": payload.get("org_id"),
        }
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.PyJWTError:
        raise HTTPException(status_code=401, detail="Invalid token")

def require_role(required_role: str):
    """Dependency to check user role."""
    async def role_checker(current_user: Dict = Depends(get_current_user)):
        if current_user["role"] != required_role and current_user["role"] != "admin":
            raise HTTPException(status_code=403, detail="Insufficient permissions")
        return current_user
    return role_checker

# =============================================================================
# Placeholder email functions (implement with your email service)
# =============================================================================

async def send_welcome_email(email: str, username: str):
    """Send welcome email (to be implemented)."""
    logger.info(f"Sending welcome email to {email} (user {username})")

async def send_reset_email(email: str, token: str):
    """Send password reset email with token."""
    logger.info(f"Sending reset email to {email} with token {token}")