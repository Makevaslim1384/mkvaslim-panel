"""
MaKeVaslim Panel - Database Layer
SQLite (local) + Cloudflare D1 (edge) dual persistence with sync.
"""
import asyncio
import json
import os
import sqlite3
import time
from contextlib import asynccontextmanager
from dataclasses import dataclass, asdict
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union
import aiosqlite
import httpx

from .config import settings


# ═══════════════════════════════════════════════════════════════════════════════
# Data Models
# ═══════════════════════════════════════════════════════════════════════════════

@dataclass
class User:
    id: Optional[int] = None
    username: str = ""
    uuid: str = ""
    limit_gb: float = 0.0          # 0 = unlimited
    expiry_days: int = 0           # 0 = no expiry
    limit_req: int = 0             # daily request limit, 0 = unlimited
    used_req: int = 0
    used_gb: float = 0.0
    is_active: int = 1
    max_connections: int = 0       # 0 = unlimited
    tls: str = "tls"
    port: str = "443"
    fingerprint: str = "chrome"
    ips: str = ""
    connection_type: str = "vless"
    created_at: str = ""
    last_active: Optional[int] = None

    # Runtime fields (not stored in DB)
    is_online: int = 0
    online_count: int = 0

    def to_dict(self, include_runtime: bool = True) -> dict:
        d = asdict(self)
        if not include_runtime:
            d.pop("is_online", None)
            d.pop("online_count", None)
        return d

    @classmethod
    def from_row(cls, row: sqlite3.Row) -> "User":
        return cls(
            id=row["id"],
            username=row["username"],
            uuid=row["uuid"],
            limit_gb=row["limit_gb"] or 0.0,
            expiry_days=row["expiry_days"] or 0,
            limit_req=row["limit_req"] or 0,
            used_req=row["used_req"] or 0,
            used_gb=row["used_gb"] or 0.0,
            is_active=row["is_active"] or 1,
            max_connections=row["max_connections"] or 0,
            tls=row["tls"] or "tls",
            port=row["port"] or "443",
            fingerprint=row["fingerprint"] or "chrome",
            ips=row["ips"] or "",
            connection_type=row["connection_type"] or "vless",
            created_at=row["created_at"] or "",
            last_active=row["last_active"],
            is_online=row["is_online"] if "is_online" in row.keys() else 0,
            online_count=row["online_count"] if "online_count" in row.keys() else 0,
        )

    def is_expired(self) -> bool:
        if self.expiry_days and self.created_at:
            try:
                created = datetime.fromisoformat(self.created_at.replace("Z", "+00:00"))
                expiry = created.timestamp() + self.expiry_days * 86400
                return time.time() > expiry
            except Exception:
                return False
        return False

    def is_allowed(self) -> bool:
        if not self.is_active:
            return False
        if self.is_expired():
            return False
        if self.limit_gb > 0 and self.used_gb >= self.limit_gb:
            return False
        if self.limit_req > 0 and self.used_req >= self.limit_req:
            return False
        return True


@dataclass
class Setting:
    key: str
    value: str


# ══════════════════════════════════════════════════════════════════════════════════
# Database Manager
# ═════════════════════════════════════════════════════════════════════════════════

class DatabaseManager:
    """
    Manages SQLite database with connection pooling and Cloudflare D1 sync.
    """

    def __init__(self, db_path: Path):
        self.db_path = db_path
        self._pool: List[aiosqlite.Connection] = []
        self._pool_size = 10
        self._lock = asyncio.Lock()
        self._d1_client: Optional[httpx.AsyncClient] = None
        self._sync_lock = asyncio.Lock()
        self._last_sync = 0
        self._sync_interval = 300  # 5 minutes

    async def initialize(self):
        """Initialize database schema and connection pool."""
        # Ensure directory exists
        self.db_path.parent.mkdir(parents=True, exist_ok=True)

        # Create schema
        async with aiosqlite.connect(self.db_path) as db:
            db.row_factory = aiosqlite.Row
            await self._create_schema(db)
            await db.commit()

        # Warm up connection pool
        for _ in range(min(3, self._pool_size)):
            conn = await aiosqlite.connect(self.db_path)
            conn.row_factory = aiosqlite.Row
            self._pool.append(conn)

        # Initialize D1 client if configured
        if settings.CF_API_TOKEN and settings.CF_ACCOUNT_ID:
            self._d1_client = httpx.AsyncClient(
                base_url=f"https://api.cloudflare.com/client/v4/accounts/{settings.CF_ACCOUNT_ID}/d1/database",
                headers={
                    "Authorization": f"Bearer {settings.CF_API_TOKEN}",
                    "Content-Type": "application/json",
                },
                timeout=30.0,
            )

        # Start background sync task
        asyncio.create_task(self._sync_loop())

    async def _create_schema(self, db: aiosqlite.Connection):
        """Create all tables and indexes."""
        # Users table
        await db.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                uuid TEXT UNIQUE NOT NULL,
                limit_gb REAL DEFAULT 0,
                expiry_days INTEGER DEFAULT 0,
                limit_req INTEGER DEFAULT 0,
                used_req INTEGER DEFAULT 0,
                used_gb REAL DEFAULT 0,
                is_active INTEGER DEFAULT 1,
                max_connections INTEGER DEFAULT 0,
                tls TEXT DEFAULT 'tls',
                port TEXT DEFAULT '443',
                fingerprint TEXT DEFAULT 'chrome',
                ips TEXT DEFAULT '',
                connection_type TEXT DEFAULT 'vless',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_active INTEGER
            )
        """)

        # Settings table
        await db.execute("""
            CREATE TABLE IF NOT EXISTS settings (
                key TEXT PRIMARY KEY,
                value TEXT
            )
        """)

        # Connection logs (for analytics)
        await db.execute("""
            CREATE TABLE IF NOT EXISTS connection_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL,
                ip TEXT,
                transport TEXT,
                bytes_up INTEGER DEFAULT 0,
                bytes_down INTEGER DEFAULT 0,
                connected_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                disconnected_at TIMESTAMP,
                duration_sec INTEGER
            )
        """)

        # Traffic hourly aggregates
        await db.execute("""
            CREATE TABLE IF NOT EXISTS traffic_hourly (
                hour TEXT PRIMARY KEY,  -- YYYY-MM-DD HH:00
                bytes_up INTEGER DEFAULT 0,
                bytes_down INTEGER DEFAULT 0,
                requests INTEGER DEFAULT 0,
                unique_users INTEGER DEFAULT 0
            )
        """)

        # Indexes
        await db.execute("CREATE INDEX IF NOT EXISTS idx_users_uuid ON users(uuid)")
        await db.execute("CREATE INDEX IF NOT EXISTS idx_users_username ON users(username)")
        await db.execute("CREATE INDEX IF NOT EXISTS idx_users_active ON users(is_active)")
        await db.execute("CREATE INDEX IF NOT EXISTS idx_logs_username ON connection_logs(username)")
        await db.execute("CREATE INDEX IF NOT EXISTS idx_logs_time ON connection_logs(connected_at)")

    # ═══════════════════════════════════════════════════════════════════════════════════
    # Connection Pool
    # ══════════════════════════════════════════════════════════════════════════════════

    @asynccontextmanager
    async def connection(self):
        """Get a connection from pool or create new one."""
        async with self._lock:
            if self._pool:
                conn = self._pool.pop()
            else:
                conn = await aiosqlite.connect(self.db_path)
                conn.row_factory = aiosqlite.Row

        try:
            yield conn
        finally:
            async with self._lock:
                if len(self._pool) < self._pool_size:
                    self._pool.append(conn)
                else:
                    await conn.close()

    async def execute(self, query: str, params: tuple = ()) -> aiosqlite.Cursor:
        """Execute a write query."""
        async with self.connection() as conn:
            cursor = await conn.execute(query, params)
            await conn.commit()
            return cursor

    async def fetchone(self, query: str, params: tuple = ()) -> Optional[aiosqlite.Row]:
        """Fetch single row."""
        async with self.connection() as conn:
            cursor = await conn.execute(query, params)
            return await cursor.fetchone()

    async def fetchall(self, query: str, params: tuple = ()) -> List[aiosqlite.Row]:
        """Fetch all rows."""
        async with self.connection() as conn:
            cursor = await conn.execute(query, params)
            return await cursor.fetchall()

    # ══════════════════════════════════════════════════════════════════════════════════
    # User CRUD
    # ═══════════════════════════════════════════════════════════════════════════════════

    async def create_user(self, user: User) -> User:
        """Create new user."""
        if not user.created_at:
            user.created_at = datetime.now().isoformat()

        cursor = await self.execute("""
            INSERT INTO users (username, uuid, limit_gb, expiry_days, limit_req,
                              used_req, used_gb, is_active, max_connections,
                              tls, port, fingerprint, ips, connection_type, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            user.username, user.uuid, user.limit_gb, user.expiry_days, user.limit_req,
            user.used_req, user.used_gb, user.is_active, user.max_connections,
            user.tls, user.port, user.fingerprint, user.ips, user.connection_type, user.created_at
        ))
        user.id = cursor.lastrowid
        return user

    async def get_user_by_uuid(self, uuid: str) -> Optional[User]:
        row = await self.fetchone("SELECT * FROM users WHERE uuid = ?", (uuid,))
        return User.from_row(row) if row else None

    async def get_user_by_username(self, username: str) -> Optional[User]:
        row = await self.fetchone("SELECT * FROM users WHERE username = ?", (username,))
        return User.from_row(row) if row else None

    async def get_user(self, identifier: str) -> Optional[User]:
        """Get user by UUID or username."""
        user = await self.get_user_by_uuid(identifier)
        if not user:
            user = await self.get_user_by_username(identifier)
        return user

    async def update_user(self, username: str, **fields) -> bool:
        """Update user fields."""
        if not fields:
            return False

        # Build dynamic query
        set_clause = ", ".join(f"{k} = ?" for k in fields.keys())
        values = list(fields.values()) + [username]

        cursor = await self.execute(
            f"UPDATE users SET {set_clause} WHERE username = ?",
            tuple(values)
        )
        return cursor.rowcount > 0

    async def delete_user(self, username: str) -> bool:
        cursor = await self.execute("DELETE FROM users WHERE username = ?", (username,))
        return cursor.rowcount > 0

    async def list_users(self, limit: int = 1000, offset: int = 0) -> List[User]:
        rows = await self.fetchall(
            "SELECT * FROM users ORDER BY id DESC LIMIT ? OFFSET ?",
            (limit, offset)
        )
        return [User.from_row(r) for r in rows]

    async def count_users(self) -> int:
        row = await self.fetchone("SELECT COUNT(*) as cnt FROM users")
        return row["cnt"] if row else 0

    async def get_active_users(self) -> List[User]:
        rows = await self.fetchall("SELECT * FROM users WHERE is_active = 1")
        return [User.from_row(r) for r in rows]

    # ═════════════════════════════════════════════════════════════════════════════════
    # Traffic & Usage
    # ═════════════════════════════════════════════════════════════════════════════════

    async def add_traffic(self, username: str, bytes_up: int = 0, bytes_down: int = 0) -> bool:
        """Add traffic to user's usage."""
        gb_up = bytes_up / (1024 ** 3)
        gb_down = bytes_down / (1024 ** 3)
        total_gb = gb_up + gb_down

        if total_gb <= 0:
            return True

        cursor = await self.execute("""
            UPDATE users SET used_gb = used_gb + ? WHERE username = ?
        """, (total_gb, username))
        return cursor.rowcount > 0

    async def add_request(self, username: str, count: int = 1) -> bool:
        """Increment request counter."""
        cursor = await self.execute("""
            UPDATE users SET used_req = used_req + ? WHERE username = ?
        """, (count, username))
        return cursor.rowcount > 0

    async def reset_usage(self, username: str, reset_type: str) -> bool:
        """Reset user usage (volume, req, or time)."""
        if reset_type == "volume":
            cursor = await self.execute("UPDATE users SET used_gb = 0 WHERE username = ?", (username,))
        elif reset_type == "req":
            cursor = await self.execute("UPDATE users SET used_req = 0 WHERE username = ?", (username,))
        elif reset_type == "time":
            cursor = await self.execute(
                "UPDATE users SET created_at = CURRENT_TIMESTAMP WHERE username = ?",
                (username,)
            )
        else:
            return False
        return cursor.rowcount > 0

    async def toggle_active(self, username: str) -> Optional[bool]:
        """Toggle user active status."""
        row = await self.fetchone("SELECT is_active FROM users WHERE username = ?", (username,))
        if not row:
            return None
        new_status = 0 if row["is_active"] else 1
        cursor = await self.execute(
            "UPDATE users SET is_active = ? WHERE username = ?",
            (new_status, username)
        )
        return new_status == 1 if cursor.rowcount > 0 else None

    # ════════════════════════════════════════════════════════════════════════════════
    # Connection Logging
    # ═════════════════════════════════════════════════════════════════════════════════

    async def log_connection_start(
        self, username: str, ip: str, transport: str
    ) -> int:
        """Log connection start, return log ID."""
        cursor = await self.execute("""
            INSERT INTO connection_logs (username, ip, transport, connected_at)
            VALUES (?, ?, ?, CURRENT_TIMESTAMP)
        """, (username, ip, transport))
        return cursor.lastrowid

    async def log_connection_end(
        self, log_id: int, bytes_up: int, bytes_down: int
    ):
        """Log connection end with traffic stats."""
        await self.execute("""
            UPDATE connection_logs
            SET disconnected_at = CURRENT_TIMESTAMP,
                bytes_up = ?, bytes_down = ?,
                duration_sec = CAST((julianday(CURRENT_TIMESTAMP) - julianday(connected_at)) * 86400 AS INTEGER)
            WHERE id = ?
        """, (bytes_up, bytes_down, log_id))

    # ═════════════════════════════════════════════════════════════════════════════════
    # Settings
    # ═════════════════════════════════════════════════════════════════════════════════

    async def get_setting(self, key: str, default: str = "") -> str:
        row = await self.fetchone("SELECT value FROM settings WHERE key = ?", (key,))
        return row["value"] if row else default

    async def set_setting(self, key: str, value: str) -> bool:
        cursor = await self.execute("""
            INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)
        """, (key, value))
        return cursor.rowcount > 0

    async def get_all_settings(self) -> Dict[str, str]:
        rows = await self.fetchall("SELECT key, value FROM settings")
        return {r["key"]: r["value"] for r in rows}

    # ══════════════════════════════════════════════════════════════════════════════════
    # Analytics & Stats
    # ══════════════════════════════════════════════════════════════════════════════════

    async def get_stats(self) -> dict:
        async with self.get_db() as db:
            async with db.execute("SELECT COUNT(*) FROM users") as cursor:
                total_users = (await cursor.fetchone())[0]
            async with db.execute("SELECT COUNT(*) FROM users WHERE is_active = 1") as cursor:
                active_users = (await cursor.fetchone())[0]
            async with db.execute("SELECT SUM(used_traffic_bytes) FROM users") as cursor:
                total_traffic = (await cursor.fetchone())[0] or 0
                
        uptime = int(time.time() - getattr(settings, "START_TIME", time.time()))
        
        return {
            "total_users": total_users,
            "active_users": active_users,
            "total_traffic_bytes": total_traffic,
            "uptime_seconds": uptime
        }
            
        # Users
        total_users = await self.count_users()
        active_users_row = await self.fetchone(
            "SELECT COUNT(*) as cnt FROM users WHERE is_active = 1"
        )
        active_users = active_users_row["cnt"] if active_users_row else 0

        # Traffic
        traffic_row = await self.fetchone("""
            SELECT SUM(used_gb) as total_gb FROM users
        """)
        total_traffic_gb = traffic_row["total_gb"] if traffic_row and traffic_row["total_gb"] else 0.0

        # Requests
        req_total = int(await self.get_setting("req_total", "0"))
        req_today = int(await self.get_setting("req_today", "0"))

        # Hourly traffic
        hourly = {}
        rows = await self.fetchall("SELECT hour, bytes_up + bytes_down as total FROM traffic_hourly ORDER BY hour DESC LIMIT 24")
        for r in rows:
            hourly[r["hour"]] = r["total"]

        # Online users (from runtime - would need connection manager)
        online_count = 0  # Filled by connection manager

        return {
            "total_users": total_users,
            "active_users": active_users,
            "total_traffic_gb": round(total_traffic_gb, 2),
            "req_total": req_total,
            "req_today": req_today,
            "online_users": online_count,
            "hourly_traffic": hourly,
            "uptime_seconds": int(time.time() - getattr(settings, "START_TIME", time.time()))
    
    return {
        "total_users": total_users,
        "active_users": active_users,
        "total_traffic_bytes": total_traffic,
        "uptime_seconds": uptime,
        }

    # ═══════════════════════════════════════════════════════════════════════════════════
    # Cloudflare D1 Sync
    # ══════════════════════════════════════════════════════════════════════════════════════

    async def _sync_to_d1(self):
        """Sync local SQLite to Cloudflare D1."""
        if not self._d1_client:
            return

        async with self._sync_lock:
            try:
                users = await self.list_users(limit=10000)
                if not users:
                    return

                # Build batch statements
                statements = []
                for u in users:
                    stmt = {
                        "sql": """INSERT OR REPLACE INTO users
                            (id, username, uuid, limit_gb, expiry_days, limit_req,
                             used_req, used_gb, is_active, max_connections,
                             tls, port, fingerprint, ips, connection_type, created_at, last_active)
                            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                        "params": [
                            u.id, u.username, u.uuid, u.limit_gb, u.expiry_days, u.limit_req,
                            u.used_req, u.used_gb, u.is_active, u.max_connections,
                            u.tls, u.port, u.fingerprint, u.ips, u.connection_type,
                            u.created_at, u.last_active
                        ]
                    }
                    statements.append(stmt)

                # Execute batch
                if statements:
                    await self._d1_client.post(
                        "/<DATABASE_ID>/batch",
                        json={"statements": statements}
                    )

                # Sync settings
                settings_data = await self.get_all_settings()
                for key, value in settings_data.items():
                    await self._d1_client.post(
                        "/<DATABASE_ID>/query",
                        json={
                            "sql": "INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)",
                            "params": [key, value]
                        }
                    )

                self._last_sync = time.time()

            except Exception as e:
                print(f"D1 sync error: {e}")

    async def _sync_from_d1(self):
        """Sync from Cloudflare D1 to local (for disaster recovery)."""
        # Implementation would fetch from D1 and update local
        pass

    async def _sync_loop(self):
        """Background sync loop."""
        while True:
            await asyncio.sleep(self._sync_interval)
            if self._d1_client:
                await self._sync_to_d1()

    async def force_sync(self):
        """Force immediate sync."""
        await self._sync_to_d1()

    # ══════════════════════════════════════════════════════════════════════════════════════════════════
    # Backup & Restore
    # ══════════════════════════════════════════════════════════════════════════════════════════════════════════════

    async def backup(self, path: Optional[Path] = None) -> Path:
        """Create database backup."""
        if path is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            path = settings.BACKUP_DIR / f"backup_{timestamp}.db"

        # Use SQLite backup API
        async with aiosqlite.connect(self.db_path) as src:
            async with aiosqlite.connect(path) as dst:
                await src.backup(dst)

        return path

    async def restore(self, path: Path) -> bool:
        """Restore from backup."""
        if not path.exists():
            return False

        async with aiosqlite.connect(path) as src:
            async with aiosqlite.connect(self.db_path) as dst:
                await src.backup(dst)
        return True

    async def list_backups(self) -> List[Path]:
        return sorted(settings.BACKUP_DIR.glob("backup_*.db"), reverse=True)

    async def cleanup_old_backups(self, keep: int = 10):
        backups = await self.list_backups()
        for old in backups[keep:]:
            try:
                old.unlink()
            except Exception:
                pass

    # ════════════════════════════════════════════════════════════════════════════════════════════════════════════════════
    # Cleanup
    # ═════════════════════════════════════════════════════════════════════════════════════════════════════════════════

    async def close(self):
        """Close all connections."""
        for conn in self._pool:
            await conn.close()
        self._pool.clear()

        if self._d1_client:
            await self._d1_client.aclose()


# Global database instance
_db_manager: Optional[DatabaseManager] = None


async def get_db() -> DatabaseManager:
    """Get global database manager instance."""
    global _db_manager
    if _db_manager is None:
        _db_manager = DatabaseManager(settings.DB_PATH)
        await _db_manager.initialize()
    return _db_manager


async def close_db():
    """Close database connections."""
    global _db_manager
    if _db_manager:
        await _db_manager.close()
        _db_manager = None
