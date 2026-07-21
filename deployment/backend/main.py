"""
MaKeVaslim Panel - Main FastAPI Application
Complete VPN panel with all protocols, transports, and management features.
"""
import asyncio
import json
import os
import secrets
import time
import hashlib
import base64
from contextlib import asynccontextmanager
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional, List, Dict, Any, Union
from dataclasses import dataclass, asdict

from fastapi import FastAPI, Request, Response, HTTPException, Depends, WebSocket, WebSocketDisconnect, Query, Form, File, UploadFile
from fastapi.responses import HTMLResponse, JSONResponse, StreamingResponse, RedirectResponse, FileResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.staticfiles import StaticFiles
import uvicorn
import httpx

from .config import settings
from database import get_db, close_db, DatabaseManager, User
from auth import (
    get_current_user, require_auth, require_admin, login_user, logout_user,
    get_password_hash, set_password_hash, create_session, validate_session,
    destroy_session, set_session_cookie, clear_session_cookie,
    session_cleanup_loop, create_access_token, decode_access_token
)
from protocols import (
    generate_all_links, generate_subscription_text, ProtocolConfig,
    generate_vless, generate_vmess, generate_trojan, generate_shadowsocks,
    generate_hysteria2, generate_tuic, generate_wireguard
)
from transports import (
    get_transport, get_all_transports, cleanup_all_transports,
    parse_vless_header, check_quota, get_client_ip, tune_socket,
    open_tcp_connection, relay_ws_to_tcp, relay_tcp_to_ws,
    XHTTP_MODES, WSTransport, XHTTPTransport
)
from limits import (
    throttle_user, throttle_connection, check_user_quota, check_connection_quota,
    reset_user_limit, reset_connection_limit, get_user_limit_stats,
    AdaptiveQuotaGate, AdaptiveFlow, record_traffic, get_hourly_traffic,
    get_current_hour_traffic, parse_speed_limit, format_speed
)
from api import auth as auth_api
from api import configs as configs_api
from api import groups as groups_api
from api import subscriptions as subs_api
from api import stats as stats_api
from api import users as users_api
from api import cloudflare as cf_api


# ═══════════════════════════════════════════════════════════════════════════════
# Application State
# ══════════════════════════════════════════════════════════════════════════════

# Global state
START_TIME = time.time()
app_start_time = START_TIME

# Active connections tracking (for stats)
active_ws_connections: Dict[str, Dict] = {}
active_xhttp_sessions: Dict[str, Dict] = {}


# ═══════════════════════════════════════════════════════════════════════════════
# Lifespan
# ═══════════════════════════════════════════════════════════════════════════════

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan manager."""
    global START_TIME

    # Startup
    START_TIME = time.time()
    print(f"🚀 Starting {settings.APP_NAME} v{settings.APP_VERSION}")

    # Initialize database
    db = await get_db()
    print(f"📊 Database initialized: {settings.DB_PATH}")

    # Initialize transports
    for mode in XHTTP_MODES:
        get_transport(f"xhttp-{mode}")
    get_transport("ws")
    print(f"🔌 Transports initialized: ws, {', '.join(f'xhttp-{m}' for m in XHTTP_MODES)}")

    # Start background tasks
    asyncio.create_task(session_cleanup_loop())
    asyncio.create_task(cleanup_expired_connections())
    print("🧹 Background tasks started")

    # Initialize HTTP client for Cloudflare
    app.state.http_client = httpx.AsyncClient(
        limits=httpx.Limits(max_connections=500, max_keepalive_connections=100),
        timeout=httpx.Timeout(30.0, connect=10.0),
        follow_redirects=True,
    )

    # Force initial DB sync if Cloudflare configured
    if settings.CF_API_TOKEN and settings.CF_ACCOUNT_ID:
        try:
            await db.force_sync()
            print("☁️ Cloudflare D1 sync completed")
        except Exception as e:
            print(f"⚠️ D1 sync failed: {e}")

    print(f"✅ {settings.APP_NAME} ready on http://{settings.HOST}:{settings.PORT}")

    yield

    # Shutdown
    print("🛑 Shutting down...")
    await cleanup_all_transports()
    await close_db()
    await app.state.http_client.aclose()
    print("✅ Shutdown complete")


# ═══════════════════════════════════════════════════════════════════════════════
# FastAPI App
# ═══════════════════════════════════════════════════════════════════════════════

app = FastAPI(
    title=f"{settings.APP_NAME} Panel",
    version=settings.APP_VERSION,
    description="Complete VPN Management Panel with Multi-Protocol Support",
    docs_url="/docs" if settings.DEBUG else None,
    redoc_url="/redoc" if settings.DEBUG else None,
    lifespan=lifespan,
)

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Security
security = HTTPBearer(auto_error=False)


# ═══════════════════════════════════════════════════════════════════════════════
# Helper Functions
# ═══════════════════════════════════════════════════════════════════════════════

def get_host(request: Request) -> str:
    """Get host from request headers."""
    host = request.headers.get("x-forwarded-host") or request.headers.get("host", "")
    if host:
        return host.split(":")[0]
    return settings.PUBLIC_DOMAIN or "localhost"


def fmt_bytes(b: int) -> str:
    """Format bytes to human readable."""
    if b < 1024: return f"{b} B"
    if b < 1024**2: return f"{b/1024:.1f} KB"
    if b < 1024**3: return f"{b/1024**2:.2f} MB"
    return f"{b/1024**3:.2f} GB"


def get_uptime() -> str:
    secs = int(time.time() - START_TIME)
    h, m, s = secs // 3600, (secs % 3600) // 60, secs % 60
    return f"{h:02d}:{m:02d}:{s:02d}"


async def cleanup_expired_connections():
    """Background task to clean expired connections."""
    while True:
        await asyncio.sleep(60)
        now = time.time()
        # Clean WS connections
        expired = [
            cid for cid, c in active_ws_connections.items()
            if now - c.get("last_activity", 0) > 300
        ]
        for cid in expired:
            active_ws_connections.pop(cid, None)
        # Clean XHTTP sessions
        expired = [
            sid for sid, s in active_xhttp_sessions.items()
            if now - s.get("last_activity", 0) > 300
        ]
        for sid in expired:
            active_xhttp_sessions.pop(sid, None)


# ═══════════════════════════════════════════════════════════════════════════════
# Static Files & Templates
# ═══════════════════════════════════════════════════════════════════════════════

# Mount static files
frontend_path = Path(__file__).parent.parent / "frontend"
if frontend_path.exists():
    app.mount("/static", StaticFiles(directory=str(frontend_path / "assets")), name="static")


# ════════════════════════════════════════════════════════════════════════════════
# Core Routes
# ═══════════════════════════════════════════════════════════════════════════════

@app.get("/")
async def root():
    return {
        "service": settings.APP_NAME,
        "version": settings.APP_VERSION,
        "status": "active",
        "uptime": get_uptime(),
        "docs": "/docs" if settings.DEBUG else "disabled",
    }


@app.get("/health")
async def health():
    return {
        "status": "ok",
        "uptime": get_uptime(),
        "version": settings.APP_VERSION,
        "connections": len(active_ws_connections) + len(active_xhttp_sessions),
    }


# ═══════════════════════════════════════════════════════════════════════════════
# Authentication Routes
# ═══════════════════════════════════════════════════════════════════════════════

@app.post("/api/login")
async def api_login(request: Request, response: Response):
    body = await request.json()
    password = body.get("password", "")

    db = await get_db()
    result = await login_user(db, password, request, response)

    if result.success:
        return {"success": True, "token": result.token}
    raise HTTPException(status_code=401, detail=result.error or "Invalid password")


@app.post("/api/logout")
async def api_logout(request: Request, response: Response):
    await logout_user(request, response)
    return {"success": True}


@app.get("/api/me")
async def api_me(user: User = Depends(get_current_user)):
    if not user:
        return {"authenticated": False}
    return {
        "authenticated": True,
        "username": user.username,
        "is_admin": True,
    }


@app.post("/api/change-password")
async def api_change_password(request: Request, user: User = Depends(require_auth)):
    body = await request.json()
    current = body.get("current_password", "")
    new = body.get("new_password", "")

    if not current or not new:
        raise HTTPException(400, "Current and new password required")
    if len(new) < 4:
        raise HTTPException(400, "New password must be at least 4 characters")

    db = await get_db()
    current_hash = await get_password_hash(db)
    if not verify_password(current, current_hash):
        raise HTTPException(400, "Current password incorrect")

    await set_password_hash(db, new)
    return {"success": True}


# ═══════════════════════════════════════════════════════════════════════════════
# Include API Routers
# ═══════════════════════════════════════════════════════════════════════════════

app.include_router(auth_api.router, prefix="/api", tags=["Auth"])
app.include_router(configs_api.router, prefix="/api", tags=["Configs"])
app.include_router(groups_api.router, prefix="/api", tags=["Groups"])
app.include_router(subs_api.router, prefix="/api", tags=["Subscriptions"])
app.include_router(stats_api.router, prefix="/api", tags=["Stats"])
app.include_router(users_api.router, prefix="/api", tags=["Users"])
app.include_router(cf_api.router, prefix="/api", tags=["Cloudflare"])


# ═══════════════════════════════════════════════════════════════════════════════
# Config/Link Generation Routes
# ═══════════════════════════════════════════════════════════════════════════════

@app.get("/sub/{uuid}")
async def subscription_single(uuid: str, request: Request):
    """Single config subscription (Base64 encoded VLESS link)."""
    db = await get_db()
    user = await db.get_user_by_uuid(uuid)

    if not user or not user.is_allowed():
        raise HTTPException(404, "Not found or inactive")

    host = get_host(request)
    ports = [int(p) for p in (user.port or "443").split(",") if p.strip().isdigit()]

    config = ProtocolConfig(
        uuid=user.uuid,
        host=host,
        port=ports[0] if ports else 443,
        remark=user.username,
        transport="ws",
        fingerprint=user.fingerprint or "chrome",
        alpn="",
        sni=host,
        path="/Ma_Ke_Vaslim",
        host_header=host,
        security="tls",
    )

    vless = generate_vless(config)
    encoded = base64.b64encode(vless.encode()).decode()

    return Response(
        content=encoded,
        media_type="text/plain",
        headers={
            "profile-title": user.username,
            "support-url": "https://t.me/MakeVaslim",
            "profile-update-interval": "12",
        }
    )


@app.get("/sub-all")
async def subscription_all(request: Request, user: User = Depends(require_auth)):
    """All configs subscription (admin only)."""
    db = await get_db()
    users = await db.list_users(limit=10000)
    host = get_host(request)

    links = []
    for u in users:
        if u.is_allowed():
            ports = [int(p) for p in (u.port or "443").split(",") if p.strip().isdigit()]
            config = ProtocolConfig(
                uuid=u.uuid,
                host=host,
                port=ports[0] if ports else 443,
                remark=u.username,
                transport="ws",
                fingerprint=u.fingerprint or "chrome",
                alpn="",
                sni=host,
                path="/Ma_Ke_Vaslim",
                host_header=host,
                security="tls",
            )
            links.append(generate_vless(config))

    content = base64.b64encode("\n".join(links).encode()).decode()
    return Response(content=content, media_type="text/plain")


# ═══════════════════════════════════════════════════════════════════════════════
# WebSocket Endpoints
# ═══════════════════════════════════════════════════════════════════════════════

@app.websocket("/ws/{uuid}")
async def websocket_vless(ws: WebSocket, uuid: str):
    """VLESS over WebSocket endpoint."""
    db = await get_db()
    user = await db.get_user_by_uuid(uuid)

    if not user or not user.is_allowed():
        await ws.close(code=4003, reason="Not authorized")
        return

    # Track connection
    conn_id = secrets.token_urlsafe(8)
    ip = get_client_ip(ws)
    active_ws_connections[conn_id] = {
        "uuid": uuid,
        "ip": ip,
        "connected_at": time.time(),
        "last_activity": time.time(),
        "bytes_up": 0,
        "bytes_down": 0,
    }

    try:
        transport = get_transport("ws")
        await transport.handle_websocket(ws, uuid, conn_id)
    finally:
        active_ws_connections.pop(conn_id, None)


# ═══════════════════════════════════════════════════════════════════════════════
# XHTTP Endpoints
# ═══════════════════════════════════════════════════════════════════════════════

@app.get("/xhttp/{mode}/{uuid}/{session_id}")
async def xhttp_downlink(mode: str, uuid: str, session_id: str, request: Request):
    """XHTTP Downlink (server -> client)."""
    if mode not in XHTTP_MODES:
        raise HTTPException(404, "Invalid mode")

    db = await get_db()
    user = await db.get_user_by_uuid(uuid)
    if not user or not user.is_allowed():
        raise HTTPException(403, "Not authorized")

    transport = get_transport(f"xhttp-{mode}")
    return await transport.handle_downlink(uuid, session_id)


@app.post("/xhttp/{mode}/{uuid}/{session_id}")
async def xhttp_uplink(mode: str, uuid: str, session_id: str, request: Request):
    """XHTTP Uplink (client -> server)."""
    if mode not in XHTTP_MODES:
        raise HTTPException(404, "Invalid mode")

    db = await get_db()
    user = await db.get_user_by_uuid(uuid)
    if not user or not user.is_allowed():
        raise HTTPException(403, "Not authorized")

    transport = get_transport(f"xhttp-{mode}")
    return await transport.handle_uplink(request, uuid, session_id)


# ═══════════════════════════════════════════════════════════════════════════════
# Subscription & Public Pages
# ═══════════════════════════════════════════════════════════════════════════════

@app.get("/sub/{uuid}")
async def sub_text(uuid: str, request: Request):
    """Text subscription (single config)."""
    db = await get_db()
    user = await db.get_user_by_uuid(uuid)
    if not user or not user.is_allowed():
        raise HTTPException(404, "Not found")

    host = get_host(request)
    ports = [int(p) for p in (user.port or "443").split(",") if p.strip().isdigit()]

    config = ProtocolConfig(
        uuid=user.uuid,
        host=host,
        port=ports[0] if ports else 443,
        remark=user.username,
        transport="ws",
        fingerprint=user.fingerprint or "chrome",
        alpn="",
        sni=host,
        path="/Ma_Ke_Vaslim",
        host_header=host,
        security="tls",
    )

    vless = generate_vless(config)
    return Response(content=vless, media_type="text/plain")


@app.get("/sub-base64/{uuid}")
async def sub_base64(uuid: str, request: Request):
    """Base64 encoded subscription."""
    db = await get_db()
    user = await db.get_user_by_uuid(uuid)
    if not user or not user.is_allowed():
        raise HTTPException(404, "Not found")

    host = get_host(request)
    ports = [int(p) for p in (user.port or "443").split(",") if p.strip().isdigit()]

    config = ProtocolConfig(
        uuid=user.uuid,
        host=host,
        port=ports[0] if ports else 443,
        remark=user.username,
        transport="ws",
        fingerprint=user.fingerprint or "chrome",
        alpn="",
        sni=host,
        path="/Ma_Ke_Vaslim",
        host_header=host,
        security="tls",
    )

    vless = generate_vless(config)
    encoded = base64.b64encode(vless.encode()).decode()
    return Response(content=encoded, media_type="text/plain")


# ═══════════════════════════════════════════════════════════════════════════════
# Frontend Routes (Panel UI)
# ═══════════════════════════════════════════════════════════════════════════════

@app.get("/panel", response_class=HTMLResponse)
@app.get("/panel/", response_class=HTMLResponse)
async def panel(request: Request):
    """Main panel UI."""
    user = await get_current_user(request)
    if not user:
        return RedirectResponse(url="/login")

    # Serve the panel HTML
    panel_html = frontend_path / "panel.html"
    if panel_html.exists():
        return FileResponse(panel_html)
    return HTMLResponse("<h1>Panel UI not found</h1>", status_code=404)


@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
    user = await get_current_user(request)
    if user:
        return RedirectResponse(url="/panel")

    login_html = frontend_path / "login.html"
    if login_html.exists():
        return FileResponse(login_html)
    return HTMLResponse("<h1>Login page not found</h1>", status_code=404)


@app.get("/sub-view", response_class=HTMLResponse)
async def sub_view_page(request: Request):
    """Public subscription view page."""
    sub_html = frontend_path / "sub-view.html"
    if sub_html.exists():
        return FileResponse(sub_html)
    return HTMLResponse("<h1>Sub view not found</h1>", status_code=404)


@app.get("/status/{username}", response_class=HTMLResponse)
async def status_page(username: str, request: Request):
    """User status page."""
    status_html = frontend_path / "status.html"
    if status_html.exists():
        return FileResponse(status_html)
    return HTMLResponse("<h1>Status page not found</h1>", status_code=404)


# ═══════════════════════════════════════════════════════════════════════════════
# Config Generation (API for panel)
# ═══════════════════════════════════════════════════════════════════════════════

@app.get("/api/config/{uuid}")
async def get_config_links(uuid: str, request: Request, user: User = Depends(require_auth)):
    """Get all protocol links for a user."""
    db = await get_db()
    target = await db.get_user_by_uuid(uuid)
    if not target:
        raise HTTPException(404, "User not found")

    host = get_host(request)
    ports = [int(p) for p in (target.port or "443").split(",") if p.strip().isdigit()]

    all_links = {}
    for port in ports:
        config = ProtocolConfig(
            uuid=target.uuid,
            host=host,
            port=port,
            remark=f"{target.username} | {port}",
            transport="ws",
            fingerprint=target.fingerprint or "chrome",
            alpn="",
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

    return {
        "username": target.username,
        "uuid": target.uuid,
        "links": all_links,
        "sub_url": f"{request.url.scheme}://{host}/sub/{uuid}",
        "sub_base64": f"{request.url.scheme}://{host}/sub-base64/{uuid}",
    }


@app.get("/api/config/{uuid}/qr")
async def get_config_qr(uuid: str, protocol: str = "vless", request: Request = None, user: User = Depends(require_auth)):
    """Generate QR code for config."""
    import qrcode
    from io import BytesIO

    db = await get_db()
    target = await db.get_user_by_uuid(uuid)
    if not target:
        raise HTTPException(404, "User not found")

    host = get_host(request) if request else settings.PUBLIC_DOMAIN
    ports = [int(p) for p in (target.port or "443").split(",") if p.strip().isdigit()]
    port = ports[0] if ports else 443

    config = ProtocolConfig(
        uuid=target.uuid,
        host=host,
        port=port,
        remark=target.username,
        transport="ws",
        fingerprint=target.fingerprint or "chrome",
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


# ═══════════════════════════════════════════════════════════════════════════════
# Stats & Monitoring
# ══════════════════════════════════════════════════════════════════════════════

@app.get("/api/stats")
async def get_stats(user: User = Depends(require_auth)):
    db = await get_db()
    stats = await db.get_stats()

    # Add rate limit stats
    stats["rate_limits"] = {}
    # Would iterate over users and get stats

    stats["ws_connections"] = len(active_ws_connections)
    stats["xhttp_sessions"] = len(active_xhttp_sessions)
    stats["hourly_traffic"] = get_hourly_traffic(24)
    stats["current_hour"] = get_current_hour_traffic()

    return stats


@app.get("/api/connections")
async def get_connections(user: User = Depends(require_auth)):
    """Get active connections grouped by IP."""
    # Group by IP
    grouped = defaultdict(lambda: {
        "sessions": 0,
        "bytes_up": 0,
        "bytes_down": 0,
        "ips": set(),
        "transports": set(),
    })

    for conn in active_ws_connections.values():
        ip = conn.get("ip", "unknown")
        g = grouped[ip]
        g["sessions"] += 1
        g["bytes_up"] += conn.get("bytes_up", 0)
        g["bytes_down"] += conn.get("bytes_down", 0)
        g["ips"].add(ip)
        g["transports"].add("ws")

    for session in active_xhttp_sessions.values():
        ip = session.get("ip", "unknown")
        g = grouped[ip]
        g["sessions"] += 1
        g["transports"].add(session.get("mode", "xhttp"))

    result = []
    for ip, data in grouped.items():
        result.append({
            "ip": ip,
            "sessions": data["sessions"],
            "bytes_up": data["bytes_up"],
            "bytes_down": data["bytes_down"],
            "total_bytes": data["bytes_up"] + data["bytes_down"],
            "transports": list(data["transports"]),
        })

    return {"connections": result, "total": len(result)}


# ═══════════════════════════════════════════════════════════════════════════════
# Backup & Restore
# ═══════════════════════════════════════════════════════════════════════════════

@app.post("/api/backup")
async def create_backup(user: User = Depends(require_auth)):
    db = await get_db()
    path = await db.backup()
    return FileResponse(
        path,
        media_type="application/octet-stream",
        filename=path.name
    )


@app.post("/api/restore")
async def restore_backup(file: UploadFile = File(...), user: User = Depends(require_auth)):
    if not file.filename.endswith(".db"):
        raise HTTPException(400, "Invalid backup file")

    db = await get_db()
    # Save uploaded file
    import tempfile
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tmp:
        content = await file.read()
        tmp.write(content)
        tmp_path = Path(tmp.name)

    success = await db.restore(tmp_path)
    tmp_path.unlink(missing_ok=True)

    if success:
        return {"success": True, "message": "Backup restored successfully"}
    raise HTTPException(500, "Restore failed")


@app.get("/api/backups")
async def list_backups(user: User = Depends(require_auth)):
    db = await get_db()
    backups = await db.list_backups()
    return {
        "backups": [
            {
                "name": b.name,
                "size": b.stat().st_size,
                "created": datetime.fromtimestamp(b.stat().st_mtime).isoformat(),
            }
            for b in backups
        ]
    }


# ════════════════════════════════════════════════════════════════════════════════
# Cloudflare Integration
# ═══════════════════════════════════════════════════════════════════════════════

@app.get("/api/cf/locations")
async def cf_locations(user: User = Depends(require_auth)):
    """Get Cloudflare PoP locations."""
    try:
        async with app.state.http_client as client:
            resp = await client.get("https://speed.cloudflare.com/locations")
            return resp.json()
    except Exception as e:
        raise HTTPException(500, f"Failed to fetch locations: {e}")


@app.get("/api/cf/usage")
async def cf_usage(user: User = Depends(require_auth)):
    """Get Cloudflare Workers usage stats."""
    if not settings.CF_API_TOKEN or not settings.CF_ACCOUNT_ID:
        raise HTTPException(400, "Cloudflare not configured")

    try:
        async with app.state.http_client as client:
            now = datetime.now()
            start_of_day = datetime(now.year, now.month, now.day).isoformat()
            thirty_days_ago = (now - timedelta(days=30)).isoformat()

            query = f"""
            query {{
                viewer {{
                    accounts(filter: {{accountTag: "{settings.CF_ACCOUNT_ID}"}}) {{
                        today: workersInvocationsAdaptive(limit: 10, filter: {{datetime_geq: "{start_of_day}"}}) {{
                            sum {{ requests }}
                        }}
                        total: workersInvocationsAdaptive(limit: 10, filter: {{datetime_geq: "{thirty_days_ago}"}}) {{
                            sum {{ requests }}
                        }}
                    }}
                }}
            }}
            """
            resp = await app.state.http_client.post(
                "https://api.cloudflare.com/client/v4/graphql",
                headers={"Authorization": f"Bearer {settings.CF_API_TOKEN}", "Content-Type": "application/json"},
                json={"query": query}
            )
            return resp.json()
    except Exception as e:
        raise HTTPException(500, f"Failed to fetch usage: {e}")


# ════════════════════════════════════════════════════════════════════════════════
# Auto-Update
# ═══════════════════════════════════════════════════════════════════════════════

@app.post("/api/update")
async def auto_update(user: User = Depends(require_auth)):
    """Trigger panel auto-update from GitHub."""
    if not settings.CF_API_TOKEN or not settings.CF_ACCOUNT_ID:
        raise HTTPException(400, "Cloudflare not configured for auto-update")

    try:
        # Fetch latest code from GitHub
        async with app.state.http_client as client:
            resp = await client.get(
                "https://raw.githubusercontent.com/MakeVaslim/Panel/main/backend/main.py",
                headers={"Cache-Control": "no-cache"}
            )
            new_code = resp.text

        # Deploy to Cloudflare Worker
        script_name = settings.CF_WORKER_NAME
        async with app.state.http_client as client:
            # Get current bindings
            bindings_resp = await client.get(
                f"https://api.cloudflare.com/client/v4/accounts/{settings.CF_ACCOUNT_ID}/workers/scripts/{script_name}/bindings",
                headers={"Authorization": f"Bearer {settings.CF_API_TOKEN}"}
            )
            bindings_data = bindings_resp.json()

            new_bindings = []
            for b in bindings_data.get("result", []):
                if b["type"] == "d1":
                    new_bindings.append({"type": "d1", "name": b["name"], "id": b.get("database_id") or b["id"]})
                elif b["name"] in ("CF_API_TOKEN", "CF_ACCOUNT_ID"):
                    new_bindings.append({"type": "secret_text", "name": b["name"], "text": getattr(settings, b["name"])})

            metadata = {
                "main_module": "main.py",
                "compatibility_date": "2024-01-01",
                "bindings": new_bindings,
            }

            # Deploy
            import aiofiles
            form_data = {
                "metadata": (None, json.dumps(metadata), "application/json"),
                "main.py": ("main.py", new_code, "application/javascript"),
            }

            deploy_resp = await client.put(
                f"https://api.cloudflare.com/client/v4/accounts/{settings.CF_ACCOUNT_ID}/workers/scripts/{script_name}",
                headers={"Authorization": f"Bearer {settings.CF_API_TOKEN}"},
                files=form_data,
            )

            if deploy_resp.status_code == 200:
                return {"success": True, "message": "Update deployed successfully"}
            else:
                raise HTTPException(500, f"Deploy failed: {deploy_resp.text}")

    except Exception as e:
        raise HTTPException(500, f"Update failed: {str(e)}")


# ═══════════════════════════════════════════════════════════════════════════════
# Export Config
# ═══════════════════════════════════════════════════════════════════════════════

@app.get("/api/export")
async def export_config(user: User = Depends(require_auth)):
    """Export all users and settings as JSON."""
    db = await get_db()
    users = await db.list_users(limit=10000)
    settings_data = await db.get_all_settings()

    export_data = {
        "version": settings.APP_VERSION,
        "exported_at": datetime.now().isoformat(),
        "users": [u.to_dict(include_runtime=False) for u in users],
        "settings": settings_data,
    }

    return Response(
        content=json.dumps(export_data, indent=2, ensure_ascii=False),
        media_type="application/json",
        headers={"Content-Disposition": f'attachment; filename="makevaslim_export_{datetime.now().strftime("%Y%m%d")}.json"'}
    )


@app.post("/api/import")
async def import_config(file: UploadFile = File(...), user: User = Depends(require_auth)):
    if not file.filename.endswith(".json"):
        raise HTTPException(400, "Invalid file format")

    try:
        content = await file.read()
        data = json.loads(content)

        db = await get_db()
        imported = 0

        for u_data in data.get("users", []):
            # Remove runtime fields
            u_data.pop("is_online", None)
            u_data.pop("online_count", None)
            u_data.pop("id", None)  # Let DB assign

            # Check if exists
            existing = await db.get_user_by_username(u_data["username"])
            if existing:
                # Update
                u_data.pop("username", None)  # Can't change username via import
                await db.update_user(existing.username, **u_data)
            else:
                # Create new
                u = User(**u_data)
                await db.create_user(u)
            imported += 1

        return {"success": True, "imported": imported}
    except Exception as e:
        raise HTTPException(500, f"Import failed: {str(e)}")


# ════════════════════════════════════════════════════════════════════════════════
# Main
# ═══════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    uvicorn.run(
        "main:app",
        host=settings.HOST,
        port=settings.PORT,
        reload=settings.DEBUG,
        log_level=settings.LOG_LEVEL.lower(),
    )