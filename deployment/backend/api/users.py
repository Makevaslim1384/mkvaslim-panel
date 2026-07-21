"""
MaKeVaslim Panel - Users API
"""
from typing import List, Optional
from fastapi import APIRouter, Request, HTTPException, Query, Depends, File, UploadFile
from pydantic import BaseModel

from ..database import get_db, DatabaseManager, User
from ..auth import require_auth, require_admin, get_password_hash, set_password_hash, verify_password
from .config import settings
import json

router = APIRouter(prefix="/api", tags=["Users"])


# ══════════════════════════════════════════════════════════════════════════════════
# Pydantic Models
# ═════════════════════════════════════════════════════════════════════════════════

class UserCreate(BaseModel):
    username: str
    password: str = ""
    limit_gb: float = 0
    limit_mb: float = 0
    limit_kb: float = 0
    speed_mbps: float = 0
    speed_kbps: float = 0
    ip_limit: int = 0
    max_connections: int = 0
    expiry_days: int = 0
    protocol: str = "vless"
    transport: str = "ws"
    fingerprint: str = "chrome"
    alpn: str = ""
    port: str = "443"
    ips: str = ""


class UserUpdate(BaseModel):
    password: Optional[str] = None
    limit_gb: Optional[float] = None
    limit_mb: Optional[float] = None
    limit_kb: Optional[float] = None
    speed_mbps: Optional[float] = None
    speed_kbps: Optional[float] = None
    ip_limit: Optional[int] = None
    max_connections: Optional[int] = None
    expiry_days: Optional[int] = None
    protocol: Optional[str] = None
    transport: Optional[str] = None
    fingerprint: Optional[str] = None
    alpn: Optional[str] = None
    port: Optional[str] = None
    ips: Optional[str] = None
    active: Optional[bool] = None
    reset_usage: bool = False
    reset_type: Optional[str] = None  # volume, req, time


class UserResponse(BaseModel):
    id: Optional[int]
    username: str
    uuid: str
    limit_gb: float
    used_gb: float
    speed_mbps: float
    ip_limit: int
    max_connections: int
    expiry_days: int
    expiry_date: Optional[str]
    protocol: str
    transport: str
    fingerprint: str
    alpn: str
    port: str
    ips: str
    active: bool
    created_at: str
    used_bytes: int
    limit_bytes: int
    speed_limit_bps: int
    used_req: int
    limit_req: int


# ═════════════════════════════════════════════════════════════════════════════════
# Helper Functions
# ═══════════════════════════════════════════════════════════════════════════════

def parse_limit(limit_gb: float, limit_mb: float, limit_kb: float) -> int:
    total = 0
    if limit_gb > 0:
        total += int(limit_gb * 1024 * 1024 * 1024)
    if limit_mb > 0:
        total += int(limit_mb * 1024 * 1024)
    if limit_kb > 0:
        total += int(limit_kb * 1024)
    return total


def parse_speed(speed_mbps: float, speed_kbps: float) -> int:
    if speed_mbps > 0:
        return int(speed_mbps * 1_000_000 / 8)
    if speed_kbps > 0:
        return int(speed_kbps * 1024)
    return 0


def fmt_bytes(b: int) -> str:
    if b < 1024: return f"{b} B"
    if b < 1024**2: return f"{b/1024:.1f} KB"
    if b < 1024**3: return f"{b/1024**2:.2f} MB"
    return f"{b/1024**3:.2f} GB"


def user_to_response(u) -> UserResponse:
    return UserResponse(
        id=u.id,
        username=u.username,
        uuid=u.uuid,
        limit_gb=round(u.limit_bytes / (1024**3), 2) if u.limit_bytes else 0,
        used_gb=round(u.used_bytes / (1024**3), 2) if u.used_bytes else 0,
        speed_mbps=round(u.speed_limit_bps * 8 / 1_000_000, 1) if u.speed_limit_bps else 0,
        ip_limit=u.ip_limit,
        max_connections=u.max_connections,
        expiry_days=u.expiry_days,
        expiry_date=u.expires_at,
        protocol=u.protocol,
        transport=u.transport,
        fingerprint=u.fingerprint,
        alpn=u.alpn,
        port=u.port,
        ips=u.ips,
        active=bool(u.active),
        created_at=u.created_at,
        used_bytes=u.used_bytes,
        limit_bytes=u.limit_bytes,
        speed_limit_bps=u.speed_limit_bps,
        used_req=u.used_req,
        limit_req=u.limit_req,
    )


# ══════════════════════════════════════════════════════════════════════════════════
# Routes
# ═════════════════════════════════════════════════════════════════════════════════

@router.get("/users")
async def list_users(
    page: int = Query(1, ge=1),
    limit: int = Query(20, ge=1, le=100),
    search: str = Query(""),
    status: str = Query("all"),
    sort: str = Query("newest"),
    user: User = Depends(require_auth)
):
    db = await get_db()
    all_users = await db.list_users(limit=10000)

    # Filter
    filtered = []
    for u in all_users:
        if search and search.lower() not in u.username.lower() and search.lower() not in u.uuid.lower():
            continue
        if status == "active" and not (u.active and not u.is_expired()):
            continue
        if status == "inactive" and u.active:
            continue
        if status == "expired" and not u.is_expired():
            continue
        if status == "online" and not u.is_online:
            continue
        filtered.append(u)

    # Sort
    if sort == "newest":
        filtered.sort(key=lambda x: x.created_at, reverse=True)
    elif sort == "oldest":
        filtered.sort(key=lambda x: x.created_at)
    elif sort == "usage_desc":
        filtered.sort(key=lambda x: x.used_bytes, reverse=True)
    elif sort == "usage_asc":
        filtered.sort(key=lambda x: x.used_bytes)
    elif sort == "name":
        filtered.sort(key=lambda x: x.username)
    elif sort == "expiry_asc":
        filtered.sort(key=lambda x: (x.expires_at or "zzzzzzzz"))

    # Pagination
    total = len(filtered)
    start = (page - 1) * limit
    paginated = filtered[start:start + limit]

    return {
        "users": [user_to_response(u) for u in paginated],
        "total": total,
        "page": page,
        "limit": limit,
        "pages": (total + limit - 1) // limit,
    }


@router.post("/users")
async def create_user(
    data: UserCreate,
    user: User = Depends(require_admin)
):
    db = await get_db()

    # Check if username exists
    existing = await db.get_user_by_username(data.username)
    if existing:
        raise HTTPException(400, "Username already exists")

    # Parse limits
    limit_bytes = parse_limit(data.limit_gb, data.limit_mb, data.limit_kb)
    speed_bps = parse_speed(data.speed_mbps, data.speed_kbps)

    # Generate UUID
    import uuid as uuid_lib
    config_uuid = str(uuid_lib.uuid4())

    # Calculate expiry
    expires_at = None
    if data.expiry_days > 0:
        expires_at = (datetime.now() + timedelta(days=data.expiry_days)).isoformat()

    # Create user
    u = User(
        username=data.username,
        uuid=config_uuid,
        limit_bytes=limit_bytes,
        used_bytes=0,
        speed_limit_bps=speed_bps,
        ip_limit=data.ip_limit,
        max_connections=data.max_connections,
        expiry_days=data.expiry_days,
        expires_at=expires_at,
        ips=data.ips,
        protocol=data.protocol,
        transport=data.transport,
        fingerprint=data.fingerprint,
        alpn=data.alpn,
        port=data.port,
        active=True,
    )

    await db.create_user(u)

    return user_to_response(u)


@router.get("/users/{username}")
async def get_user(
    username: str,
    user: User = Depends(require_auth)
):
    db = await get_db()
    u = await db.get_user_by_username(username)
    if not u:
        raise HTTPException(404, "User not found")
    return user_to_response(u)


@router.patch("/users/{username}")
async def update_user(
    username: str,
    data: UserUpdate,
    user: User = Depends(require_admin)
):
    db = await get_db()
    u = await db.get_user_by_username(username)
    if not u:
        raise HTTPException(404, "User not found")

    update_data = {}

    if data.password is not None:
        if data.password:
            update_data["password_hash"] = await set_password_hash(db, data.password)
        else:
            # Can't clear password hash easily, would need special handling
            pass

    if data.limit_gb is not None or data.limit_mb is not None or data.limit_kb is not None:
        limit_bytes = parse_limit(
            data.limit_gb or 0,
            data.limit_mb or 0,
            data.limit_kb or 0
        )
        update_data["limit_bytes"] = limit_bytes

    if data.speed_mbps is not None or data.speed_kbps is not None:
        speed_bps = parse_speed(data.speed_mbps or 0, data.speed_kbps or 0)
        update_data["speed_limit_bps"] = speed_bps

    if data.ip_limit is not None:
        update_data["ip_limit"] = data.ip_limit
    if data.max_connections is not None:
        update_data["max_connections"] = data.max_connections
    if data.expiry_days is not None:
        update_data["expiry_days"] = data.expiry_days
        if data.expiry_days > 0:
            update_data["expires_at"] = (datetime.now() + timedelta(days=data.expiry_days)).isoformat()
        else:
            update_data["expires_at"] = None

    if data.protocol is not None:
        update_data["protocol"] = data.protocol
    if data.transport is not None:
        update_data["transport"] = data.transport
    if data.fingerprint is not None:
        update_data["fingerprint"] = data.fingerprint
    if data.alpn is not None:
        update_data["alpn"] = data.alpn
    if data.port is not None:
        update_data["port"] = data.port
    if data.ips is not None:
        update_data["ips"] = data.ips
    if data.active is not None:
        update_data["active"] = 1 if data.active else 0

    if data.reset_usage:
        if data.reset_type == "volume":
            update_data["used_bytes"] = 0
        elif data.reset_type == "req":
            update_data["used_req"] = 0
        elif data.reset_type == "time":
            update_data["created_at"] = datetime.now().isoformat()

    if update_data:
        await db.update_user(username, **update_data)
        u = await db.get_user_by_username(username)

    return user_to_response(u)


@router.delete("/users/{username}")
async def delete_user(
    username: str,
    user: User = Depends(require_admin)
):
    db = await get_db()
    u = await db.get_user_by_username(username)
    if not u:
        raise HTTPException(404, "User not found")

    await db.delete_user(username)
    return {"success": True, "message": f"User {username} deleted"}


@router.post("/users/{username}/toggle")
async def toggle_user(
    username: str,
    user: User = Depends(require_admin)
):
    db = await get_db()
    u = await db.get_user_by_username(username)
    if not u:
        raise HTTPException(404, "User not found")

    new_status = 0 if u.active else 1
    await db.update_user(username, active=new_status)
    return {"success": True, "active": bool(new_status)}


@router.post("/users/{username}/reset-usage")
async def reset_user_usage(
    username: str,
    reset_type: str = Query("volume", regex="^(volume|req|time)$"),
    user: User = Depends(require_admin)
):
    db = await get_db()
    u = await db.get_user_by_username(username)
    if not u:
        raise HTTPException(404, "User not found")

    if reset_type == "volume":
        await db.update_user(username, used_bytes=0)
    elif reset_type == "req":
        await db.update_user(username, used_req=0)
    elif reset_type == "time":
        await db.update_user(username, created_at=datetime.now().isoformat())

    return {"success": True, "message": f"{reset_type} usage reset"}


@router.get("/users/{username}/links")
async def get_user_links(
    username: str,
    request: Request,
    user: User = Depends(require_auth)
):
    db = await get_db()
    u = await db.get_user_by_username(username)
    if not u:
        raise HTTPException(404, "User not found")

    host = request.headers.get("host", "").split(":")[0] or settings.PUBLIC_DOMAIN
    ports = [int(p) for p in (u.port or "443").split(",") if p.strip().isdigit()]

    from ..protocols import build_links
    links = build_links(u, host, ports)

    return {
        "username": u.username,
        "uuid": u.uuid,
        "links": links,
        "sub_url": f"https://{host}/sub/{u.uuid}",
        "sub_base64": f"https://{host}/sub-base64/{u.uuid}",
    }


@router.get("/users/{username}/qr")
async def get_user_qr(
    username: str,
    protocol: str = Query("vless"),
    request: Request = None,
    user: User = Depends(require_auth)
):
    import qrcode
    from io import BytesIO
    from ..protocols import ProtocolConfig, generate_vless, generate_vmess, generate_trojan, generate_shadowsocks, generate_hysteria2, generate_tuic

    db = await get_db()
    u = await db.get_user_by_username(username)
    if not u:
        raise HTTPException(404, "User not found")

    host = request.headers.get("host", "").split(":")[0] or settings.PUBLIC_DOMAIN
    ports = [int(p) for p in (u.port or "443").split(",") if p.strip().isdigit()]
    port = ports[0] if ports else 443

    config = ProtocolConfig(
        uuid=u.uuid,
        host=host,
        port=port,
        remark=u.label,
        transport="ws",
        fingerprint=u.fingerprint or "chrome",
        alpn="",
        sni=host,
        path="/Ma_Ke_Vaslim",
        host_header=host,
        security="tls",
    )

    generators = {
        "vless": generate_vless,
        "vmess": generate_vmess,
        "trojan": generate_trojan,
        "shadowsocks": generate_shadowsocks,
        "hysteria2": generate_hysteria2,
        "tuic": generate_tuic,
    }

    gen_func = generators.get(protocol, generate_vless)
    link = gen_func(config)

    qr = qrcode.make(link)
    buf = BytesIO()
    qr.save(buf, format="PNG")
    buf.seek(0)

    return StreamingResponse(buf, media_type="image/png")


# ═══════════════════════════════════════════════════════════════════════════════════
# Bulk Operations
# ═══════════════════════════════════════════════════════════════════════════════════

class BulkActionRequest(BaseModel):
    usernames: List[str]
    action: str  # delete, activate, deactivate, reset_volume, reset_req, reset_time


@router.post("/users/bulk")
async def bulk_users_action(
    data: BulkActionRequest,
    user: User = Depends(require_admin)
):
    db = await get_db()
    success = 0
    failed = 0

    for username in data.usernames:
        u = await db.get_user_by_username(username)
        if not u:
            failed += 1
            continue

        try:
            if data.action == "delete":
                await db.delete_user(username)
            elif data.action == "activate":
                await db.update_user(username, active=1)
            elif data.action == "deactivate":
                await db.update_user(username, active=0)
            elif data.action == "reset_volume":
                await db.update_user(username, used_bytes=0)
            elif data.action == "reset_req":
                await db.update_user(username, used_req=0)
            elif data.action == "reset_time":
                await db.update_user(username, created_at=datetime.now().isoformat())
            else:
                failed += 1
                continue
            success += 1
        except Exception:
            failed += 1

    return {"success": success, "failed": failed, "message": f"Processed {success} users, {failed} failed"}


from datetime import datetime, timedelta
from fastapi.responses import StreamingResponse
from typing import List