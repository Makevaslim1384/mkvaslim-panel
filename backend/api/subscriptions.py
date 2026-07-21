"""
MaKeVaslim Panel - Subscriptions API
"""
from fastapi import APIRouter, Request, HTTPException, Query, Depends
from typing import List, Optional

from ..database import get_db, DatabaseManager, User, User
from ..auth import require_auth, require_admin
from ..protocols import generate_subscription_text
from ..config import settings
import base64

router = APIRouter(prefix="/api", tags=["Subscriptions"])


@router.get("/subscriptions")
async def list_subscriptions(
    request: Request,
    user: User = Depends(require_auth)
):
    """List all subscription types and links."""
    host = request.headers.get("host", "").split(":")[0] or settings.PUBLIC_DOMAIN

    return {
        "single": f"https://{host}/sub/{{uuid}}",
        "all": f"https://{host}/sub-all",
        "groups": f"https://{host}/api/groups",
        "formats": {
            "text": "Plain text VLESS links",
            "base64": "Base64 encoded for clients",
            "json": "JSON with metadata",
        }
    }


@router.get("/sub-all")
async def sub_all(request: Request, user: User = Depends(require_auth)):
    """All configs subscription (admin only, requires auth cookie)."""
    db = await get_db()
    users = await db.list_users(limit=10000)
    host = request.headers.get("host", "").split(":")[0] or settings.PUBLIC_DOMAIN

    links = []
    for u in users:
        if u.is_allowed():
            ports = [int(p) for p in (u.port or "443").split(",") if p.strip().isdigit()]
            config = ProtocolConfig(
                uuid=u.uuid,
                host=host,
                port=ports[0] if ports else 443,
                remark=u.label,
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
    return Response(
        content=content,
        media_type="text/plain",
        headers={
            "profile-title": "All Configs",
            "support-url": "https://t.me/MakeVaslim",
            "profile-update-interval": "12",
        }
    )


@router.get("/subscriptions/formats")
async def subscription_formats(user: User = Depends(require_auth)):
    """Get available subscription formats."""
    return {
        "formats": [
            {
                "id": "vless",
                "name": "VLESS",
                "protocols": ["vless"],
                "transports": ["ws", "h2", "grpc", "xhttp", "tcp"],
            },
            {
                "id": "vmess",
                "name": "VMESS",
                "protocols": ["vmess"],
                "transports": ["ws", "h2", "grpc", "tcp"],
            },
            {
                "id": "trojan",
                "name": "Trojan",
                "protocols": ["trojan"],
                "transports": ["ws", "h2", "grpc", "tcp"],
            },
            {
                "id": "shadowsocks",
                "name": "Shadowsocks",
                "protocols": ["shadowsocks"],
                "transports": ["tcp", "ws"],
            },
            {
                "id": "hysteria2",
                "name": "Hysteria2",
                "protocols": ["hysteria2"],
                "transports": ["quic"],
            },
            {
                "id": "tuic",
                "name": "TUIC",
                "protocols": ["tuic"],
                "transports": ["quic"],
            },
            {
                "id": "wireguard",
                "name": "WireGuard",
                "protocols": ["wireguard"],
                "transports": ["udp"],
            },
        ]
    }


@router.get("/subscriptions/export")
async def export_subscriptions(
    format: str = Query("json", regex="^(json|yaml|txt)$"),
    protocol: str = Query("all", regex="^(all|vless|vmess|trojan|shadowsocks|hysteria2|tuic|wireguard)$"),
    user: User = Depends(require_admin)
):
    """Export subscriptions in various formats."""
    db = await get_db()
    users = await db.list_users(limit=10000)
    host = settings.PUBLIC_DOMAIN

    all_links = []
    for u in users:
        if u.is_allowed():
            ports = [int(p) for p in (u.port or "443").split(",") if p.strip().isdigit()]
            for port in ports:
                config = ProtocolConfig(
                    uuid=u.uuid,
                    host=host,
                    port=port,
                    remark=f"{u.label} | {port}",
                    transport="ws",
                    fingerprint=u.fingerprint or "chrome",
                    alpn="",
                    sni=host,
                    path="/Ma_Ke_Vaslim",
                    host_header=host,
                    security="tls",
                )

                if protocol == "all" or protocol == "vless":
                    all_links.append(generate_vless(config))
                if protocol == "all" or protocol == "vmess":
                    all_links.append(generate_vmess(config))
                if protocol == "all" or protocol == "trojan":
                    all_links.append(generate_trojan(config))
                if protocol == "all" or protocol == "shadowsocks":
                    all_links.append(generate_shadowsocks(config))
                if protocol == "all" or protocol == "hysteria2":
                    all_links.append(generate_hysteria2(config))
                if protocol == "all" or protocol == "tuic":
                    all_links.append(generate_tuic(config))
                if protocol == "all" or protocol == "wireguard":
                    all_links.append(generate_wireguard(config))

    if format == "json":
        return {"links": all_links, "count": len(all_links)}
    elif format == "yaml":
        import yaml
        return Response(
            content=yaml.dump(all_links, allow_unicode=True),
            media_type="text/yaml"
        )
    else:
        return Response(
            content="\n".join(all_links),
            media_type="text/plain"
        )


@router.get("/subscriptions/stats")
async def subscription_stats(user: User = Depends(require_admin)):
    """Get subscription statistics."""
    db = await get_db()
    users = await db.list_users(limit=10000)

    stats = {
        "total_configs": len(users),
        "active_configs": sum(1 for u in users if u.active and not u.is_expired()),
        "by_protocol": {},
        "by_transport": {},
        "total_subscriptions_served": 0,  # Would need tracking
    }

    for u in users:
        if not u.is_allowed():
            continue
        proto = u.protocol
        trans = u.transport
        stats["by_protocol"][proto] = stats["by_protocol"].get(proto, 0) + 1
        stats["by_transport"][trans] = stats["by_transport"].get(trans, 0) + 1

    return stats


from datetime import datetime