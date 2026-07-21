"""
MaKeVaslim Panel - Statistics API
"""
from fastapi import APIRouter, Request, HTTPException, Query, Depends
from typing import List, Optional

from ..database import get_db, DatabaseManager
from ..auth import require_auth, require_admin
from ..limits import get_hourly_traffic, get_current_hour_traffic, get_user_limit_stats
from ..transports import get_all_transports
from .config import settings

router = APIRouter(prefix="/api", tags=["Stats"])

import sys
import time
from datetime import datetime
from typing import Optional


@router.get("/stats")
async def get_system_stats(user: User = Depends(require_auth)):
    """Get comprehensive system statistics."""
    db = await get_db()

    # Get database stats
    db_stats = await db.get_stats()

    # Add transport stats
    transports = get_all_transports()

    transport_stats = {}
    for t in transports:
        transport_stats[t.name] = {
            "active_connections": len(t.active_connections),
            "total_sessions": len(t.active_connections),  # Simplified
        }

    # Rate limit stats (sample)
    rate_limit_stats = {}

    return {
        "system": {
            "uptime_seconds": int(time.time() - START_TIME),
            "uptime_formatted": get_uptime(),
            "version": settings.APP_VERSION,
            "python_version": f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}",
        },
        "database": db_stats,
        "transports": transport_stats,
        "rate_limits": rate_limit_stats,
        "hourly_traffic": get_hourly_traffic(24),
        "current_hour": get_current_hour_traffic(),
        "timestamp": datetime.now().isoformat(),
    }


@router.get("/stats/traffic")
async def get_traffic_stats(
    hours: int = Query(24, ge=1, le=168),
    user: User = Depends(require_auth)
):
    """Get traffic statistics for specified hours."""
    return {
        "hourly": get_hourly_traffic(hours),
        "current_hour": get_current_hour_traffic(),
    }


@router.get("/stats/traffic/summary")
async def get_traffic_summary(user: User = Depends(require_auth)):
    """Get traffic summary."""
    hourly = get_hourly_traffic(24)
    current = get_current_hour_traffic()

    total_up = sum(h["up"] for h in hourly.values())
    total_down = sum(h["down"] for h in hourly.values())
    total_requests = sum(h["requests"] for h in hourly.values())

    # Peak hour
    peak_hour = max(hourly.items(), key=lambda x: x[1]["up"] + x[1]["down"], default=(None, {"up": 0, "down": 0}))

    return {
        "last_24h": {
            "total_up_gb": round(total_up / (1024**3), 2),
            "total_down_gb": round(total_down / (1024**3), 2),
            "total_gb": round((total_up + total_down) / (1024**3), 2),
            "total_requests": total_requests,
        },
        "current_hour": current,
        "peak_hour": {
            "hour": peak_hour[0],
            "up_gb": round(peak_hour[1]["up"] / (1024**3), 2),
            "down_gb": round(peak_hour[1]["down"] / (1024**3), 2),
        } if peak_hour[0] else None,
        "average_hourly_gb": round((total_up + total_down) / (1024**3) / max(len(hourly), 1), 2),
    }


@router.get("/stats/users")
async def get_user_stats(user: User = Depends(require_auth)):
    """Get user statistics."""
    db = await get_db()
    users = await db.list_users(limit=10000)

    total = len(users)
    active = sum(1 for u in users if u.active and not u.is_expired())
    expired = sum(1 for u in users if u.is_expired())
    inactive = sum(1 for u in users if not u.active)

    # Protocol distribution
    by_protocol = {}
    by_transport = {}
    for u in users:
        if u.active:
            by_protocol[u.protocol] = by_protocol.get(u.protocol, 0) + 1
            by_transport[u.transport] = by_transport.get(u.transport, 0) + 1

    # Usage stats
    total_usage_gb = sum(u.used_bytes for u in users) / (1024**3)
    total_limit_gb = sum(u.limit_bytes for u in users if u.limit_bytes > 0) / (1024**3)

    return {
        "total": total,
        "active": active,
        "expired": expired,
        "inactive": inactive,
        "by_protocol": by_protocol,
        "by_transport": by_transport,
        "usage": {
            "total_used_gb": round(total_usage_gb, 2),
            "total_limit_gb": round(total_limit_gb, 2) if total_limit_gb > 0 else None,
            "average_per_user_gb": round(total_usage_gb / max(active, 1), 2),
        }
    }


@router.get("/stats/connections")
async def get_connection_stats(user: User = Depends(require_auth)):
    """Get connection statistics."""
    transports = get_all_transports()
    total_ws = sum(len(t.active_connections) for t in transports if t.name == "ws")
    total_xhttp = sum(len(t.active_connections) for t in transports if t.name.startswith("xhttp-"))

    return {
        "websocket": total_ws,
        "xhttp": total_xhttp,
        "total": total_ws + total_xhttp,
        "by_transport": {
            t.name: len(t.active_connections) for t in transports
        }
    }


@router.get("/stats/rate-limits")
async def get_rate_limit_stats(
    uuid: Optional[str] = Query(None),
    user: User = Depends(require_auth)
):
    """Get rate limit statistics."""
    if uuid:
        return get_user_limit_stats(uuid)

    # Return sample of all users
    db = await get_db()
    users = await db.list_users(limit=50)

    result = {}
    for u in users:
        if u.speed_limit_bps > 0:
            result[u.username] = get_user_limit_stats(u.uuid)

    return {"users": result, "count": len(result)}


@router.get("/stats/errors")
async def get_error_stats(user: User = Depends(require_auth)):
    """Get recent errors."""
    db = await get_db()
    # Would query error_logs table
    return {"errors": [], "count": 0}


@router.get("/stats/performance")
async def get_performance_stats(user: User = Depends(require_admin)):
    """Get system performance metrics."""
    import psutil

    process = psutil.Process()
    mem = process.memory_info()
    cpu = process.cpu_percent(interval=0.1)

    return {
        "memory": {
            "rss_mb": round(mem.rss / 1024 / 1024, 1),
            "vms_mb": round(mem.vms / 1024 / 1024, 1),
            "percent": process.memory_percent(),
        },
        "cpu": {
            "percent": cpu,
            "cores": psutil.cpu_count(),
        },
        "disk": {
            "usage": psutil.disk_usage("/").percent,
        },
        "network": {
            "connections": len(psutil.net_connections()),
        },
        "python": {
            "version": sys.version,
            "threads": len(psutil.Process().threads()),
        },
        "uptime_seconds": int(time.time() - START_TIME),
    }


import sys
import time
from datetime import datetime
from typing import Optional