"""
MaKeVaslim Panel - Configs API
"""
from typing import List, Optional
from fastapi import APIRouter, Request, HTTPException, Query, Depends, Form, File, UploadFile
from pydantic import BaseModel
from typing import List, Optional

from ..database import get_db, DatabaseManager, User
from ..auth import require_auth, require_admin
from ..protocols import (
    generate_all_links, generate_subscription_text, ProtocolConfig,
    generate_vless, generate_vmess, generate_trojan, generate_shadowsocks,
    generate_hysteria2, generate_tuic, generate_wireguard
)
from ..config import settings
import base64

router = APIRouter(prefix="/api", tags=["Configs"])


# ═══════════════════════════════════════════════════════════════════════════════════
# Pydantic Models
# ═════════════════════════════════════════════════════════════════════════════════

class ConfigCreate(BaseModel):
    label: str = "New Config"
    protocol: str = "vless"
    transport: str = "ws"
    fingerprint: str = "chrome"
    alpn: str = ""
    port: int = 443
    limit_gb: float = 0
    limit_mb: float = 0
    limit_kb: float = 0
    speed_mbps: float = 0
    speed_kbps: float = 0
    ip_limit: int = 0
    expiry_days: int = 0
    ips: str = ""
    max_connections: int = 0
    sub_id: Optional[str] = None


class ConfigUpdate(BaseModel):
    label: Optional[str] = None
    protocol: Optional[str] = None
    transport: Optional[str] = None
    fingerprint: Optional[str] = None
    alpn: Optional[str] = None
    port: Optional[int] = None
    limit_gb: Optional[float] = None
    limit_mb: Optional[float] = None
    limit_kb: Optional[float] = None
    speed_mbps: Optional[float] = None
    speed_kbps: Optional[float] = None
    ip_limit: Optional[int] = None
    expiry_days: Optional[int] = None
    ips: Optional[str] = None
    max_connections: Optional[int] = None
    sub_id: Optional[str] = None
    active: Optional[bool] = None
    reset_usage: bool = False


class ConfigResponse(BaseModel):
    uuid: str
    label: str
    protocol: str
    transport: str
    fingerprint: str
    alpn: str
    port: int
    limit_bytes: int
    used_bytes: int
    speed_limit_bps: int
    ip_limit: int
    expiry_days: int
    expiry_date: Optional[str]
    ips: str
    max_connections: int
    active: bool
    created_at: str
    sub_id: Optional[str]
    links: dict
    sub_url: str


# ═══════════════════════════════════════════════════════════════════════════════════
# Helper Functions
# ══════════════════════════════════════════════════════════════════════════════════

def parse_limit(limit_gb: float, limit_mb: float, limit_kb: float) -> int:
    """Parse limit from GB/MB/KB to bytes."""
    total = 0
    if limit_gb > 0:
        total += int(limit_gb * 1024 * 1024 * 1024)
    if limit_mb > 0:
        total += int(limit_mb * 1024 * 1024)
    if limit_kb > 0:
        total += int(limit_kb * 1024)
    return total


def parse_speed(speed_mbps: float, speed_kbps: float) -> int:
    """Parse speed from Mbps/Kbps to bytes/sec."""
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


def user_to_response(u, host: str, links: dict) -> ConfigResponse:
    return ConfigResponse(
        uuid=u.uuid,
        label=u.label,
        protocol=u.protocol,
        transport=u.transport,
        fingerprint=u.fingerprint,
        alpn=u.alpn,
        port=u.port,
        limit_bytes=u.limit_bytes,
        used_bytes=u.used_bytes,
        speed_limit_bps=u.speed_limit_bps,
        ip_limit=u.ip_limit,
        expiry_days=u.expiry_days,
        expiry_date=u.expires_at,
        ips=u.ips,
        max_connections=u.max_connections,
        active=u.active,
        created_at=u.created_at,
        sub_id=u.sub_id,
        links=links,
        sub_url=f"https://{host}/sub/{u.uuid}",
    )


def build_links(u, host: str, ports: List[int]) -> dict:
    """Generate all protocol links for a user."""
    all_links = {}
    for port in ports:
        config = ProtocolConfig(
            uuid=u.uuid,
            host=host,
            port=port,
            remark=f"{u.label} | {port}",
            transport=u.transport,
            fingerprint=u.fingerprint or "chrome",
            alpn=u.alpn or "",
            sni=host,
            path="/Ma_Ke_Vaslim",
            host_header=host,
            security="tls",
        )

        for proto_name, gen_func in [
            ("vless", generate_vless),
            ("vmess", generate_vmess),
            ("trojan", generate_trojan),
            ("shadowsocks", generate_shadowsocks),
            ("hysteria2", generate_hysteria2),
            ("tuic", generate_tuic),
        ]:
            link = gen_func(config)
            all_links.setdefault(proto_name, []).append(link)

    return all_links


# ═══════════════════════════════════════════════════════════════════════════════════
# Routes
# ══════════════════════════════════════════════════════════════════════════════════

@router.get("/configs")
async def list_configs(
    request: Request,
    page: int = Query(1, ge=1),
    limit: int = Query(20, ge=1, le=100),
    search: str = Query(""),
    status: str = Query("all"),
    sort: str = Query("newest"),
    user: User = Depends(require_auth)
):
    """List all configs with pagination and filters."""
    db = await get_db()
    host = request.headers.get("host", "").split(":")[0] or settings.PUBLIC_DOMAIN

    # Get all users
    all_users = await db.list_users(limit=10000)

    # Filter
    filtered = []
    for u in all_users:
        if search and search.lower() not in u.label.lower() and search.lower() not in u.uuid.lower():
            continue
        if status == "active" and not u.active:
            continue
        if status == "inactive" and u.active:
            continue
        if status == "expired" and not u.is_expired():
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
        filtered.sort(key=lambda x: x.label)

    # Pagination
    total = len(filtered)
    start = (page - 1) * limit
    paginated = filtered[start:start + limit]

    # Build response
    host = host.split(":")[0] if host else settings.PUBLIC_DOMAIN
    result = []
    for u in paginated:
        ports = [int(p) for p in (u.port or "443").split(",") if p.strip().isdigit()]
        links = build_links(u, host, ports)
        result.append(user_to_response(u, host, links))

    return {
        "configs": result,
        "total": total,
        "page": page,
        "limit": limit,
        "pages": (total + limit - 1) // limit,
    }


@router.post("/configs")
async def create_config(
    data: ConfigCreate,
    request: Request,
    user: User = Depends(require_admin)
):
    """Create new config."""
    db = await get_db()
    host = request.headers.get("host", "").split(":")[0] or settings.PUBLIC_DOMAIN

    # Parse limits
    limit_bytes = parse_limit(data.limit_gb, data.limit_mb, data.limit_kb)
    speed_bps = parse_speed(data.speed_mbps, data.speed_kbps)

    # Generate UUID
    import uuid as uuid_lib
    config_uuid = str(uuid.uuid4())

    # Calculate expiry
    expires_at = None
    if data.expiry_days > 0:
        expires_at = (datetime.now() + timedelta(days=data.expiry_days)).isoformat()

    # Create user
    u = User(
        username=data.label,
        uuid=config_uuid,
        limit_bytes=limit_bytes,
        used_bytes=0,
        speed_limit_bps=speed_bps,
        ip_limit=data.ip_limit,
        expiry_days=data.expiry_days,
        expires_at=expires_at,
        ips=data.ips,
        max_connections=data.max_connections,
        protocol=data.protocol,
        transport=data.transport,
        fingerprint=data.fingerprint,
        alpn=data.alpn,
        port=data.port,
        sub_id=data.sub_id,
        active=True,
    )

    await db.create_user(u)

    # Build links
    ports = [data.port] if data.port else [443]
    links = build_links(u, host, ports)

    return user_to_response(u, host, links)


@router.get("/configs/{uuid}")
async def get_config(
    uuid: str,
    request: Request,
    user: User = Depends(require_auth)
):
    """Get single config details."""
    db = await get_db()
    u = await db.get_user_by_uuid(uuid)
    if not u:
        raise HTTPException(404, "Config not found")

    host = request.headers.get("host", "").split(":")[0] or settings.PUBLIC_DOMAIN
    ports = [int(p) for p in (u.port or "443").split(",") if p.strip().isdigit()]
    links = build_links(u, host, ports)

    return user_to_response(u, host, links)


@router.patch("/configs/{uuid}")
async def update_config(
    uuid: str,
    data: ConfigUpdate,
    request: Request,
    user: User = Depends(require_admin)
):
    """Update config."""
    db = await get_db()
    u = await db.get_user_by_uuid(uuid)
    if not u:
        raise HTTPException(404, "Config not found")

    # Build update fields
    update_data = {}

    if data.label is not None:
        update_data["label"] = data.label
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
    if data.ip_limit is not None:
        update_data["ip_limit"] = data.ip_limit
    if data.max_connections is not None:
        update_data["max_connections"] = data.max_connections
    if data.ips is not None:
        update_data["ips"] = data.ips
    if data.active is not None:
        update_data["active"] = 1 if data.active else 0
    if data.sub_id is not None:
        update_data["sub_id"] = data.sub_id

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

    if data.expiry_days is not None:
        update_data["expiry_days"] = data.expiry_days
        if data.expiry_days > 0:
            update_data["expires_at"] = (datetime.now() + timedelta(days=data.expiry_days)).isoformat()
        else:
            update_data["expires_at"] = None

    if data.reset_usage:
        update_data["used_bytes"] = 0

    if update_data:
        await db.update_user(u.username, **update_data)
        u = await db.get_user_by_uuid(uuid)

    host = request.headers.get("host", "").split(":")[0] or settings.PUBLIC_DOMAIN
    ports = [int(p) for p in (u.port or "443").split(",") if p.strip().isdigit()]
    links = build_links(u, host, ports)

    return user_to_response(u, host, links)


@router.delete("/configs/{uuid}")
async def delete_config(
    uuid: str,
    user: User = Depends(require_admin)
):
    """Delete config."""
    db = await get_db()
    u = await db.get_user_by_uuid(uuid)
    if not u:
        raise HTTPException(404, "Config not found")

    await db.delete_user(u.username)
    return {"success": True, "message": f"Config {u.label} deleted"}


@router.post("/configs/{uuid}/toggle")
async def toggle_config(
    uuid: str,
    user: User = Depends(require_admin)
):
    """Toggle config active status."""
    db = await get_db()
    u = await db.get_user_by_uuid(uuid)
    if not u:
        raise HTTPException(404, "Config not found")

    new_status = 0 if u.active else 1
    await db.update_user(u.username, active=new_status)

    return {"success": True, "active": bool(new_status)}


@router.post("/configs/{uuid}/reset-usage")
async def reset_config_usage(
    uuid: str,
    user: User = Depends(require_admin)
):
    """Reset config usage statistics."""
    db = await get_db()
    u = await db.get_user_by_uuid(uuid)
    if not u:
        raise HTTPException(404, "Config not found")

    await db.update_user(u.username, used_bytes=0)
    return {"success": True, "message": "Usage reset"}


@router.get("/configs/{uuid}/links")
async def get_config_links(
    uuid: str,
    request: Request,
    user: User = Depends(require_auth)
):
    """Get all protocol links for a config."""
    db = await get_db()
    u = await db.get_user_by_uuid(uuid)
    if not u:
        raise HTTPException(404, "Config not found")

    host = request.headers.get("host", "").split(":")[0] or settings.PUBLIC_DOMAIN
    ports = [int(p) for p in (u.port or "443").split(",") if p.strip().isdigit()]
    links = build_links(u, host, ports)

    return {
        "username": u.label,
        "uuid": u.uuid,
        "links": links,
        "sub_url": f"https://{host}/sub/{uuid}",
        "sub_base64": f"https://{host}/sub-base64/{uuid}",
    }


@router.get("/configs/{uuid}/qr")
async def get_config_qr(
    uuid: str,
    protocol: str = Query("vless"),
    request: Request = None,
    user: User = Depends(require_auth)
):
    """Generate QR code for config."""
    import qrcode
    from io import BytesIO

    db = await get_db()
    u = await db.get_user_by_uuid(uuid)
    if not u:
        raise HTTPException(404, "Config not found")

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


# Import datetime and timedelta
from datetime import datetime, timedelta
from typing import List
from fastapi.responses import StreamingResponse