"""
MaKeVaslim Panel - Cloudflare Integration API
"""
from fastapi import APIRouter, Request, HTTPException, Query, Depends, Form
from typing import List, Optional

from ..database import get_db, DatabaseManager, User, User
from ..auth import require_auth, require_admin
from ..config import settings

router = APIRouter(prefix="/api", tags=["Cloudflare"])


@router.get("/cf/locations")
async def cf_locations(user: User = Depends(require_auth)):
    """Get Cloudflare PoP locations for proxy IP selection."""
    if not settings.CF_API_TOKEN:
        raise HTTPException(400, "Cloudflare API token not configured")

    try:
        async with Request.app.state.http_client as client:
            resp = await client.get("https://speed.cloudflare.com/locations")
            return resp.json()
    except Exception as e:
        raise HTTPException(500, f"Failed to fetch locations: {e}")


@router.get("/cf/usage")
async def cf_usage(user: User = Depends(require_admin)):
    """Get Cloudflare Workers usage statistics."""
    if not settings.CF_API_TOKEN or not settings.CF_ACCOUNT_ID:
        raise HTTPException(400, "Cloudflare not configured")

    try:
        now = datetime.now()
        start_of_day = datetime(now.year, now.month, now.day).isoformat()
        thirty_days_ago = (datetime.now() - timedelta(days=30)).isoformat()

        query = f"""
        query {{
            viewer {{
                accounts(filter: {{accountTag: "{settings.CF_ACCOUNT_ID}"}}) {{
                    today: workersInvocationsAdaptive(limit: 10, filter: {{datetime_geq: "{datetime.now().date().isoformat()}"}}) {{
                        sum {{ requests }}
                    }}
                    total: workersInvocationsAdaptive(limit: 10, filter: {{datetime_geq: "{(datetime.now() - timedelta(days=30)).date().isoformat()}"}}) {{
                        sum {{ requests }}
                    }}
                }}
            }}
        """

        async with Request.app.state.http_client as client:
            resp = await Request.app.state.http_client.post(
                "https://api.cloudflare.com/client/v4/graphql",
                headers={
                    "Authorization": f"Bearer {settings.CF_API_TOKEN}",
                    "Content-Type": "application/json",
                },
                json={"query": query}
            )
            return resp.json()
    except Exception as e:
        raise HTTPException(500, f"Failed to fetch usage: {e}")


@router.get("/cf/proxy-ip")
async def get_proxy_ip(user: User = Depends(require_auth)):
    """Get current proxy IP settings."""
    db = await get_db()
    proxy_ip = await db.get_setting("proxy_ip", "proxyip.cmliussss.net")
    iata = await db.get_setting("proxy_location_iata", "")
    frag_len = await db.get_setting("frag_len", "20-30")
    frag_int = await db.get_setting("frag_int", "1-2")

    return {
        "proxy_ip": proxy_ip,
        "iata": iata,
        "frag_len": frag_len,
        "frag_int": frag_int,
    }


@router.post("/cf/proxy-ip")
async def set_proxy_ip(
    proxy_ip: str = Form(...),
    iata: str = Form(""),
    frag_len: str = Form("20-30"),
    frag_int: str = Form("1-2"),
    user: User = Depends(require_admin)
):
    """Set Cloudflare proxy IP settings."""
    db = await get_db()

    # Validate proxy IP format (basic)
    if proxy_ip and not (proxy_ip.replace(".", "").isdigit() or "." in proxy_ip):
        raise HTTPException(400, "Invalid proxy IP format")

    await db.set_setting("proxy_ip", proxy_ip)
    await db.set_setting("proxy_location_iata", iata)
    await db.set_setting("frag_len", frag_len)
    await db.set_setting("frag_int", frag_int)

    return {"success": True, "message": "Proxy IP settings updated"}


@router.get("/cf/workers")
async def list_workers(user: User = Depends(require_admin)):
    """List Cloudflare Workers scripts."""
    if not settings.CF_API_TOKEN or not settings.CF_ACCOUNT_ID:
        raise HTTPException(400, "Cloudflare not configured")

    try:
        async with Request.app.state.http_client as client:
            resp = await client.get(
                f"https://api.cloudflare.com/client/v4/accounts/{settings.CF_ACCOUNT_ID}/workers/scripts",
                headers={"Authorization": f"Bearer {settings.CF_API_TOKEN}"}
            )
            return resp.json()
    except Exception as e:
        raise HTTPException(500, f"Failed to list workers: {e}")


@router.post("/cf/workers/{script_name}/deploy")
async def deploy_worker(
    script_name: str,
    code: str = Form(...),
    user: User = Depends(require_admin)
):
    """Deploy code to Cloudflare Worker."""
    if not settings.CF_API_TOKEN or not settings.CF_ACCOUNT_ID:
        raise HTTPException(400, "Cloudflare not configured")

    try:
        import json

        async with Request.app.state.http_client as client:
            # Get current bindings
            bindings_resp = await Request.app.state.http_client.get(
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

            import aiohttp
            # Use multipart form for deployment
            import io
            form_data = aiohttp.FormData()
            form_data.add_field('metadata', json.dumps(metadata), content_type='application/json')
            form_data.add_field('main.py', code, content_type='application/javascript', filename='main.py')

            async with Request.app.state.http_client.post(
                f"https://api.cloudflare.com/client/v4/accounts/{settings.CF_ACCOUNT_ID}/workers/scripts/{script_name}",
                headers={"Authorization": f"Bearer {settings.CF_API_TOKEN}"},
                data=form_data,
            ) as deploy_resp:
                result = await deploy_resp.json()
                if result.get("success"):
                    return {"success": True, "message": "Worker deployed successfully"}
                else:
                    raise HTTPException(500, f"Deploy failed: {result}")

    except Exception as e:
        raise HTTPException(500, f"Deploy failed: {str(e)}")


@router.get("/cf/d1/databases")
async def list_d1_databases(user: User = Depends(require_admin)):
    """List Cloudflare D1 databases."""
    if not settings.CF_API_TOKEN or not settings.CF_ACCOUNT_ID:
        raise HTTPException(400, "Cloudflare not configured")

    try:
        async with Request.app.state.http_client as client:
            resp = await client.get(
                f"https://api.cloudflare.com/client/v4/accounts/{settings.CF_ACCOUNT_ID}/d1/database",
                headers={"Authorization": f"Bearer {settings.CF_API_TOKEN}"}
            )
            return resp.json()
    except Exception as e:
        raise HTTPException(500, f"Failed to list D1 databases: {e}")


@router.post("/cf/d1/query")
async def execute_d1_query(
    database_id: str = Form(...),
    sql: str = Form(...),
    user: User = Depends(require_admin)
):
    """Execute SQL query on D1 database."""
    if not settings.CF_API_TOKEN or not settings.CF_ACCOUNT_ID:
        raise HTTPException(400, "Cloudflare not configured")

    try:
        async with Request.app.state.http_client as client:
            resp = await client.post(
                f"https://api.cloudflare.com/client/v4/accounts/{settings.CF_ACCOUNT_ID}/d1/database/{database_id}/query",
                headers={
                    "Authorization": f"Bearer {settings.CF_API_TOKEN}",
                    "Content-Type": "application/json",
                },
                json={"sql": sql}
            )
            return resp.json()
    except Exception as e:
        raise HTTPException(500, f"Query failed: {e}")


@router.get("/cf/dns/records")
async def list_dns_records(
    zone_id: str = Query(...),
    user: User = Depends(require_admin)
):
    """List DNS records for a zone."""
    if not settings.CF_API_TOKEN:
        raise HTTPException(400, "Cloudflare not configured")

    try:
        async with Request.app.state.http_client as client:
            resp = await client.get(
                f"https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records",
                headers={"Authorization": f"Bearer {settings.CF_API_TOKEN}"}
            )
            return resp.json()
    except Exception as e:
        raise HTTPException(500, f"Failed to list DNS records: {e}")


@router.post("/cf/dns/records")
async def create_dns_record(
    zone_id: str = Form(...),
    type: str = Form(...),
    name: str = Form(...),
    content: str = Form(...),
    ttl: int = Form(1),
    proxied: bool = Form(False),
    user: User = Depends(require_admin)
):
    """Create DNS record."""
    if not settings.CF_API_TOKEN:
        raise HTTPException(400, "Cloudflare not configured")

    try:
        async with Request.app.state.http_client as client:
            resp = await client.post(
                f"https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records",
                headers={
                    "Authorization": f"Bearer {settings.CF_API_TOKEN}",
                    "Content-Type": "application/json",
                },
                json={
                    "type": type,
                    "name": name,
                    "content": content,
                    "ttl": ttl,
                    "proxied": proxied,
                }
            )
            return resp.json()
    except Exception as e:
        raise HTTPException(500, f"Failed to create DNS record: {e}")


@router.delete("/cf/dns/records/{identifier}")
async def delete_dns_record(
    zone_id: str,
    identifier: str,
    user: User = Depends(require_admin)
):
    """Delete DNS record."""
    if not settings.CF_API_TOKEN:
        raise HTTPException(400, "Cloudflare not configured")

    try:
        async with Request.app.state.http_client as client:
            resp = await client.delete(
                f"https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records/{identifier}",
                headers={"Authorization": f"Bearer {settings.CF_API_TOKEN}"}
            )
            return resp.json()
    except Exception as e:
        raise HTTPException(500, f"Failed to delete DNS record: {e}")