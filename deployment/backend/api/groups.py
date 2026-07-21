"""
MaKeVaslim Panel - Sub Groups API
"""
from typing import List, Optional
from fastapi import APIRouter, Request, HTTPException, Query, Depends
from pydantic import BaseModel
from typing import List, Optional

from ..database import get_db, DatabaseManager
from ..auth import require_auth, require_admin

router = APIRouter(prefix="/api", tags=["Groups"])


# ═════════════════════════════════════════════════════════════════════════════════
# Pydantic Models
# ════════════════════════════════════════════════════════════════════════════════

class GroupCreate(BaseModel):
    name: str
    description: str = ""
    password: str = ""  # Optional password for public page


class GroupUpdate(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    password: Optional[str] = None
    link_ids: Optional[List[str]] = None


class GroupResponse(BaseModel):
    sub_id: str
    name: str
    description: str
    password_hash: Optional[str]
    has_password: bool
    uuid_key: str
    created_at: str
    link_ids: List[str]
    links_count: int
    active_count: int
    total_used_bytes: int
    total_used_fmt: str
    public_url: str
    sub_url: str


# ════════════════════════════════════════════════════════════════════════════════
# Helper
# ════════════════════════════════════════════════════════════════════════════════

def fmt_bytes(b: int) -> str:
    if b < 1024: return f"{b} B"
    if b < 1024**2: return f"{b/1024:.1f} KB"
    if b < 1024**3: return f"{b/1024**2:.2f} MB"
    return f"{b/1024**3:.2f} GB"


def group_to_response(s, host: str, links_map: dict) -> GroupResponse:
    link_ids = s.get("link_ids", [])
    active_count = sum(1 for lid in link_ids if links_map.get(lid, {}).get("active", False))
    total_used = sum(links_map.get(lid, {}).get("used_bytes", 0) for lid in link_ids)

    return GroupResponse(
        sub_id=s["sub_id"],
        name=s["name"],
        description=s.get("description", ""),
        password_hash=s.get("password_hash"),
        has_password=bool(s.get("password_hash")),
        uuid_key=s["uuid_key"],
        created_at=s["created_at"],
        link_ids=link_ids,
        links_count=len(link_ids),
        active_count=active_count,
        total_used_bytes=total_used,
        total_used_fmt=fmt_bytes(total_used),
        public_url=f"https://{host}/p/{s['uuid_key']}",
        sub_url=f"https://{host}/sub-group/{s['uuid_key']}",
    )


# ════════════════════════════════════════════════════════════════════════════════
# Routes
# ═══════════════════════════════════════════════════════════════════════════════

@router.get("/groups")
async def list_groups(
    request: Request,
    page: int = Query(1, ge=1),
    limit: int = Query(20, ge=1, le=100),
    search: str = Query(""),
    user: User = Depends(require_auth)
):
    db = await get_db()
    host = request.headers.get("host", "").split(":")[0] or settings.PUBLIC_DOMAIN

    # Get all subs and links
    all_subs = await db.list_subs(limit=1000)
    all_links = await db.list_links(limit=10000)
    links_map = {l.uuid: l for l in all_links}

    filtered = []
    for s in all_subs:
        if search and search.lower() not in s.name.lower() and search.lower() not in s.get("description", "").lower():
            continue
        filtered.append(s)

    # Sort by created_at desc
    filtered.sort(key=lambda x: x.get("created_at", ""), reverse=True)

    total = len(filtered)
    start = (page - 1) * limit
    paginated = filtered[start:start + limit]

    result = [group_to_response(s, host, links_map) for s in paginated]

    return {
        "groups": result,
        "total": total,
        "page": page,
        "limit": limit,
        "pages": (total + limit - 1) // limit,
    }


@router.post("/groups")
async def create_group(
    data: GroupCreate,
    request: Request,
    user: User = Depends(require_admin)
):
    db = await get_db()
    host = request.headers.get("host", "").split(":")[0] or settings.PUBLIC_DOMAIN

    import secrets
    sub_id = secrets.token_urlsafe(16)
    uuid_key = secrets.token_urlsafe(16)

    # Hash password if provided
    password_hash = None
    if data.password:
        from ..auth import hash_password
        password_hash = hash_password(data.password)

    sub_data = {
        "sub_id": sub_id,
        "name": data.name,
        "description": data.description,
        "password_hash": password_hash,
        "uuid_key": uuid_key,
        "created_at": datetime.now().isoformat(),
        "link_ids": [],
    }

    # Store in database (we'll add a proper table later, for now use settings)
    import json
    subs_key = f"sub_{sub_id}"
    await db.set_setting(subs_key, json.dumps(sub_data))

    # Also maintain a list of all sub_ids
    subs_list = json.loads(await db.get_setting("subs_list", "[]"))
    subs_list.append(sub_id)
    await db.set_setting("subs_list", json.dumps(subs_list))

    return group_to_response(sub_data, host, {})


@router.get("/groups/{sub_id}")
async def get_group(
    sub_id: str,
    request: Request,
    user: User = Depends(require_auth)
):
    db = await get_db()
    host = request.headers.get("host", "").split(":")[0] or settings.PUBLIC_DOMAIN

    import json
    subs_key = f"sub_{sub_id}"
    sub_data = json.loads(await db.get_setting(subs_key, "{}"))
    if not sub_data.get("sub_id"):
        raise HTTPException(404, "Group not found")

    all_links = await db.list_links(limit=10000)
    links_map = {l.uuid: l for l in all_links}

    return group_to_response(sub_data, host, links_map)


@router.patch("/groups/{sub_id}")
async def update_group(
    sub_id: str,
    data: GroupUpdate,
    request: Request,
    user: User = Depends(require_admin)
):
    db = await get_db()
    host = request.headers.get("host", "").split(":")[0] or settings.PUBLIC_DOMAIN

    import json
    subs_key = f"sub_{sub_id}"
    sub_data = json.loads(await db.get_setting(subs_key, "{}"))
    if not sub_data.get("sub_id"):
        raise HTTPException(404, "Group not found")

    if data.name is not None:
        sub_data["name"] = data.name
    if data.description is not None:
        sub_data["description"] = data.description
    if data.password is not None:
        if data.password:
            from ..auth import hash_password
            sub_data["password_hash"] = hash_password(data.password)
        else:
            sub_data["password_hash"] = None
    if data.link_ids is not None:
        sub_data["link_ids"] = data.link_ids

    await db.set_setting(subs_key, json.dumps(sub_data))

    all_links = await db.list_links(limit=10000)
    links_map = {l.uuid: l for l in all_links}

    return group_to_response(sub_data, host, links_map)


@router.delete("/groups/{sub_id}")
async def delete_group(
    sub_id: str,
    user: User = Depends(require_admin)
):
    db = await get_db()

    import json
    subs_key = f"sub_{sub_id}"
    sub_data = json.loads(await db.get_setting(subs_key, "{}"))
    if not sub_data.get("sub_id"):
        raise HTTPException(404, "Group not found")

    # Remove from list
    subs_list = json.loads(await db.get_setting("subs_list", "[]"))
    if sub_id in subs_list:
        subs_list.remove(sub_id)
        await db.set_setting("subs_list", json.dumps(subs_list))

    # Delete group data
    await db.set_setting(subs_key, "")

    return {"success": True, "message": f"Group deleted"}


@router.post("/groups/{sub_id}/links")
async def add_link_to_group(
    sub_id: str,
    uuid: str,
    user: User = Depends(require_admin)
):
    db = await get_db()

    import json
    subs_key = f"sub_{sub_id}"
    sub_data = json.loads(await db.get_setting(subs_key, "{}"))
    if not sub_data.get("sub_id"):
        raise HTTPException(404, "Group not found")

    # Check if link exists
    db = await get_db()
    link = await get_db().get_user_by_uuid(uuid)
    if not link:
        raise HTTPException(404, "Config not found")

    if uuid not in sub_data.get("link_ids", []):
        sub_data.setdefault("link_ids", []).append(uuid)
        await db.set_setting(subs_key, json.dumps(sub_data))

    return {"success": True, "message": "Config added to group"}


@router.delete("/groups/{sub_id}/links/{uuid}")
async def remove_link_from_group(
    sub_id: str,
    uuid: str,
    user: User = Depends(require_admin)
):
    db = await get_db()

    import json
    subs_key = f"sub_{sub_id}"
    sub_data = json.loads(await db.get_setting(subs_key, "{}"))
    if not sub_data.get("sub_id"):
        raise HTTPException(404, "Group not found")

    if uuid in sub_data.get("link_ids", []):
        sub_data["link_ids"].remove(uuid)
        await db.set_setting(subs_key, json.dumps(sub_data))

    return {"success": True, "message": "Config removed from group"}


@router.get("/groups/{sub_id}/links/available")
async def get_available_links(
    sub_id: str,
    user: User = Depends(require_auth)
):
    """Get links not in this group for adding."""
    db = await get_db()

    import json
    subs_key = f"sub_{sub_id}"
    sub_data = json.loads(await db.get_setting(subs_key, "{}"))
    if not sub_data.get("sub_id"):
        raise HTTPException(404, "Group not found")

    current_ids = set(sub_data.get("link_ids", []))
    all_links = await db.list_links(limit=10000)

    available = []
    for l in all_links:
        if l.uuid not in current_ids:
            available.append({
                "uuid": l.uuid,
                "label": l.label,
                "protocol": l.protocol,
                "transport": l.transport,
                "used_bytes": l.used_bytes,
                "limit_bytes": l.limit_bytes,
            })

    return {"links": available}


# Import datetime
from datetime import datetime