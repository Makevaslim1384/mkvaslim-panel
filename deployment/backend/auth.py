"""
MaKeVaslim Panel - Authentication & Authorization
JWT-based sessions with HttpOnly cookies, SHA-256 password hashing.
"""
import hashlib
import secrets
import time
from contextlib import asynccontextmanager
from dataclasses import dataclass
from typing import Optional, Dict, Any
import jwt
from fastapi import Request, HTTPException, Response, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

from .config import settings
from database import get_db, DatabaseManager, User


# ══════════════════════════════════════════════════════════════════════════════
# Constants & Models
# ══════════════════════════════════════════════════════════════════════════════

SESSION_COOKIE = "mk_session"
SESSION_TTL = settings.SESSION_TTL
JWT_ALGORITHM = "HS256"
JWT_SECRET = settings.SECRET_KEY

# In-memory session store (for immediate validation)
_sessions: Dict[str, Dict[str, Any]] = {}
_sessions_lock = asyncio.Lock()

# Password hash cache
_password_hash_cache: Dict[str, str] = {}


@dataclass
class TokenPayload:
    """JWT token payload."""
    sub: str          # username
    iat: int          # issued at
    exp: int          # expiration
    jti: str          # unique token ID

    def to_dict(self) -> dict:
        return {
            "sub": self.sub,
            "iat": self.iat,
            "exp": self.exp,
            "jti": self.jti,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "TokenPayload":
        return cls(
            sub=data["sub"],
            iat=data["iat"],
            exp=data["exp"],
            jti=data["jti"],
        )


# ══════════════════════════════════════════════════════════════════════════════
# Password Hashing
# ══════════════════════════════════════════════════════════════════════════════

def hash_password(password: str) -> str:
    """Hash password with SHA-256 + secret salt."""
    # Use secret as pepper for additional security
    salted = f"{password}{JWT_SECRET}"
    return hashlib.sha256(salted.encode()).hexdigest()


def verify_password(password: str, password_hash: str) -> bool:
    """Verify password against hash."""
    return hash_password(password) == password_hash


async def get_password_hash(db: DatabaseManager) -> str:
    """Get panel password hash from database."""
    if "panel" in _password_hash_cache:
        return _password_hash_cache["panel"]

    hash_val = await db.get_setting("panel_password", "")
    _password_hash_cache["panel"] = hash_val
    return hash_val


async def set_password_hash(db: DatabaseManager, password: str) -> str:
    """Set new panel password."""
    hash_val = hash_password(password)
    await db.set_setting("panel_password", hash_val)
    _password_hash_cache["panel"] = hash_val
    # Invalidate all sessions on password change
    async with _sessions_lock:
        _sessions.clear()
    return hash_val


# ══════════════════════════════════════════════════════════════════════════════
# Session Management
# ══════════════════════════════════════════════════════════════════════════════

async def create_session(username: str) -> str:
    """Create new session token."""
    token = secrets.token_urlsafe(32)
    now = int(time.time())
    exp = now + SESSION_TTL

    session_data = {
        "username": username,
        "created": now,
        "expires": exp,
        "ip": None,  # Set on first request
    }

    async with _sessions_lock:
        _sessions[token] = session_data

    return token


async def validate_session(token: str) -> Optional[Dict[str, Any]]:
    """Validate session token and return session data."""
    if not token:
        return None

    async with _sessions_lock:
        session = _sessions.get(token)

    if not session:
        return None

    if session["expires"] < time.time():
        async with _sessions_lock:
            _sessions.pop(token, None)
        return None

    # Update last activity
    session["last_activity"] = time.time()
    return session


async def destroy_session(token: str) -> bool:
    """Destroy session."""
    async with _sessions_lock:
        if token in _sessions:
            _sessions.pop(token)
            return True
    return False


async def cleanup_expired_sessions():
    """Remove expired sessions (call periodically)."""
    now = time.time()
    async with _sessions_lock:
        expired = [t for t, s in _sessions.items() if s["expires"] < now]
        for t in expired:
            _sessions.pop(t, None)


# ══════════════════════════════════════════════════════════════════════════════
# JWT Tokens (for API access)
# ═══════════════════════════════════════════════════════════════════════════════

def create_access_token(username: str, expires_delta: int = SESSION_TTL) -> str:
    """Create JWT access token."""
    now = int(time.time())
    payload = TokenPayload(
        sub=username,
        iat=now,
        exp=now + expires_delta,
        jti=secrets.token_urlsafe(16),
    )
    return jwt.encode(payload.to_dict(), JWT_SECRET, algorithm=JWT_ALGORITHM)


def decode_access_token(token: str) -> Optional[TokenPayload]:
    """Decode and validate JWT token."""
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        return TokenPayload.from_dict(payload)
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None


# ═══════════════════════════════════════════════════════════════════════════════
# FastAPI Dependencies
# ═══════════════════════════════════════════════════════════════════════════════

security = HTTPBearer(auto_error=False)


async def get_current_session(request: Request) -> Optional[Dict[str, Any]]:
    """Get session from cookie."""
    token = request.cookies.get(SESSION_COOKIE)
    return await validate_session(token)


async def get_current_user(
    request: Request,
    db: DatabaseManager = Depends(get_db)
) -> Optional[User]:
    """Get current authenticated user."""
    session = await get_current_session(request)
    if not session:
        return None

    user = await db.get_user_by_username(session["username"])
    return user


async def require_auth(
    request: Request,
    db: DatabaseManager = Depends(get_db)
) -> User:
    """Require authentication - raise 401 if not authenticated."""
    user = await get_current_user(request, db)
    if not user:
        raise HTTPException(
            status_code=401,
            detail="Unauthorized",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return user


async def require_admin(
    request: Request,
    db: DatabaseManager = Depends(get_db)
) -> User:
    """Require admin authentication (panel access)."""
    user = await require_auth(request, db)
    # For panel, any authenticated user is admin
    # Could add role field later
    return user


# ═══════════════════════════════════════════════════════════════════════════════
# Cookie Helpers
# ═══════════════════════════════════════════════════════════════════════════════

def set_session_cookie(response: Response, token: str):
    """Set session cookie on response."""
    response.set_cookie(
        key=SESSION_COOKIE,
        value=token,
        max_age=SESSION_TTL,
        httponly=True,
        secure=True,  # Requires HTTPS
        samesite="lax",
        path="/",
    )


def clear_session_cookie(response: Response):
    """Clear session cookie."""
    response.delete_cookie(
        key=SESSION_COOKIE,
        path="/",
        httponly=True,
        secure=True,
        samesite="lax",
    )


# ═══════════════════════════════════════════════════════════════════════════════
# Login / Logout Logic
# ═══════════════════════════════════════════════════════════════════════════════

@dataclass
class LoginResult:
    success: bool
    user: Optional[User] = None
    token: Optional[str] = None
    error: Optional[str] = None


async def login_user(
    db: DatabaseManager,
    password: str,
    request: Request,
    response: Response
) -> LoginResult:
    """Authenticate user with password."""
    password_hash = await get_password_hash(db)

    if not password_hash:
        # No password set - first login
        new_hash = await set_password_hash(db, password)
        token = await create_session("admin")
        set_session_cookie(response, token)
        return LoginResult(
            success=True,
            user=User(username="admin", is_active=1),
            token=token
        )

    if not verify_password(password, password_hash):
        return LoginResult(success=False, error="Invalid password")

    token = await create_session("admin")
    set_session_cookie(response, token)
    return LoginResult(
        success=True,
        user=User(username="admin", is_active=1),
        token=token
    )


async def logout_user(request: Request, response: Response) -> bool:
    """Logout current user."""
    token = request.cookies.get(SESSION_COOKIE)
    if token:
        await destroy_session(token)
    clear_session_cookie(response)
    return True


# ══════════════════════════════════════════════════════════════════════════════
# Periodic Cleanup Task
# ══════════════════════════════════════════════════════════════════════════════

async def session_cleanup_loop():
    """Background task to clean expired sessions."""
    while True:
        await asyncio.sleep(300)  # Every 5 minutes
        await cleanup_expired_sessions()


# ═══════════════════════════════════════════════════════════════════════════════
# API Key Support (for external access)
# ═══════════════════════════════════════════════════════════════════════════════

class APIKeyManager:
    """Manage API keys for programmatic access."""

    def __init__(self, db: DatabaseManager):
        self.db = db

    async def create_key(self, name: str, permissions: list = None) -> str:
        """Create new API key."""
        key = f"mk_{secrets.token_urlsafe(32)}"
        key_hash = hashlib.sha256(key.encode()).hexdigest()

        key_data = {
            "name": name,
            "hash": key_hash,
            "permissions": permissions or ["read"],
            "created": int(time.time()),
            "last_used": None,
        }

        await self.db.set_setting(f"api_key_{key_hash}", json.dumps(key_data))
        return key

    async def validate_key(self, key: str) -> Optional[dict]:
        """Validate API key and return key data."""
        key_hash = hashlib.sha256(key.encode()).hexdigest()
        data = await self.db.get_setting(f"api_key_{key_hash}")
        if data:
            key_info = json.loads(data)
            # Update last used
            key_info["last_used"] = int(time.time())
            await self.db.set_setting(f"api_key_{key_hash}", json.dumps(key_info))
            return key_info
        return None

    async def revoke_key(self, key: str) -> bool:
        """Revoke API key."""
        key_hash = hashlib.sha256(key.encode()).hexdigest()
        return await self.db.set_setting(f"api_key_{key_hash}", "")

    async def list_keys(self) -> list:
        """List all API keys (without hashes)."""
        settings = await self.db.get_all_settings()
        keys = []
        for k, v in settings.items():
            if k.startswith("api_key_"):
                info = json.loads(v)
                keys.append({
                    "name": info["name"],
                    "permissions": info["permissions"],
                    "created": info["created"],
                    "last_used": info["last_used"],
                })
        return keys


import asyncio
import json