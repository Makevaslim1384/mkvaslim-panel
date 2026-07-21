"""
MaKeVaslim Panel - Configuration Management
Centralized config with environment variable support and validation.
"""
import os
from pathlib import Path
from typing import Optional, List, Set
from functools import lru_cache
import json


class Settings:
    """Application settings with validation and defaults."""

    def __init__(self):
        # ── Core ──────────────────────────────────────────────────────────────
        self.APP_NAME = "MaKeVaslim"
        self.APP_VERSION = "1.0.0"
        self.DEBUG = os.getenv("DEBUG", "false").lower() == "true"

        # ── Paths ─────────────────────────────────────────────────────────────
        self.DATA_DIR = Path(os.getenv("DATA_DIR", "/data")).resolve()
        self.DATA_DIR.mkdir(parents=True, exist_ok=True)

        self.DB_PATH = self.DATA_DIR / "makevaslim.db"
        self.STATE_FILE = self.DATA_DIR / "state.json"
        self.SECRET_FILE = self.DATA_DIR / "secret.key"
        self.BACKUP_DIR = self.DATA_DIR / "backups"
        self.BACKUP_DIR.mkdir(parents=True, exist_ok=True)

        # ── Network ───────────────────────────────────────────────────────────
        self.HOST = os.getenv("HOST", "0.0.0.0")
        self.PORT = int(os.getenv("PORT", "8000"))
        self.PUBLIC_DOMAIN = os.getenv("RAILWAY_PUBLIC_DOMAIN", "").strip() or os.getenv("PUBLIC_DOMAIN", "").strip()

        # ── Security ──────────────────────────────────────────────────────────
        self.ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "MakeVaslim2024!")

        # SECRET_KEY: persisted to file for session/password hash stability across restarts
        env_secret = os.getenv("SECRET_KEY")
        if env_secret:
            self.SECRET_KEY = env_secret
        else:
            self.SECRET_KEY = self._load_or_create_secret()

        self.SESSION_COOKIE = "mk_session"
        self.SESSION_TTL = 60 * 60 * 24 * 365  # 1 year
        self.PASSWORD_MIN_LENGTH = 4

        # ── Defaults for Config Creation ──────────────────────────────────────
        self.DEFAULT_PROTOCOL = "vless"
        self.PROTOCOLS = ("vless", "vmess", "trojan", "shadowsocks", "hysteria2", "tuic")

        self.DEFAULT_TRANSPORT = "ws"
        self.TRANSPORTS = ("ws", "h2", "grpc", "xhttp", "quic", "tcp")

        self.FINGERPRINTS = (
            "chrome", "firefox", "safari", "ios", "android",
            "edge", "360", "qq", "random", "randomized"
        )
        self.DEFAULT_FINGERPRINT = "chrome"

        self.DEFAULT_ALPN_BY_TRANSPORT = {
            "ws": "http/1.1",
            "h2": "h2,http/1.1",
            "grpc": "h2",
            "xhttp": "h2,http/1.1",
            "quic": "h3",
            "tcp": "http/1.1",
        }

        self.DEFAULT_PORT = 443
        self.MIN_PORT, self.MAX_PORT = 1, 65535

        # Common TLS ports for auto-TLS detection
        self.TLS_PORTS = {"443", "2053", "2083", "2087", "2096", "8443", "2095"}
        self.NON_TLS_PORTS = {"80", "8080", "8880", "2052", "2082", "2086", "2095"}

        # ── Limits ────────────────────────────────────────────────────────────
        self.DEFAULT_SPEED_LIMIT = 0  # 0 = unlimited (bytes/sec internally)
        self.MIN_SPEED_LIMIT = 1024  # 1 KB/s minimum to avoid division issues

        self.DEFAULT_IP_LIMIT = 0  # 0 = unlimited
        self.DEFAULT_CONNECTION_LIMIT = 0  # 0 = unlimited

        # Token Bucket settings
        self.TOKEN_BUCKET_REFILL_INTERVAL = 0.1  # seconds
        self.TOKEN_BUCKET_MIN_BURST = 16 * 1024  # 16 KB

        # Adaptive Quota Gate
        self.QUOTA_MIN_BATCH = 32 * 1024
        self.QUOTA_MAX_BATCH = 1 * 1024 * 1024
        self.QUOTA_START_BATCH = 64 * 1024
        self.QUOTA_CHECK_INTERVAL = 0.2

        # AIMD Flow Control
        self.FLOW_MIN_HW = 256 * 1024
        self.FLOW_MAX_HW = 16 * 1024 * 1024
        self.FLOW_START_HW = 2 * 1024 * 1024
        self.FLOW_FAST_DRAIN_MS = 2.0
        self.FLOW_SLOW_DRAIN_MS = 25.0

        # ── Cloudflare ────────────────────────────────────────────────────────
        self.CF_API_TOKEN = os.getenv("CF_API_TOKEN", "").strip()
        self.CF_ACCOUNT_ID = os.getenv("CF_ACCOUNT_ID", "").strip()
        self.CF_WORKER_NAME = os.getenv("WORKER_NAME", "makevaslim")

        # Railway backends for failover (comma-separated)
        railway_backends = os.getenv("RAILWAY_BACKENDS", "").strip()
        self.RAILWAY_BACKENDS = [b.strip() for b in railway_backends.split(",") if b.strip()] if railway_backends else [
            "makevaslim-production.up.railway.app",
        ]

        # DNS over HTTPS resolver
        self.DOH_RESOLVER = "https://1.1.1.1/dns-query"
        self.DNS_CACHE_TTL = 5 * 60 * 1000  # 5 minutes

        # ── Telegram Bot ──────────────────────────────────────────────────────
        self.TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN", "").strip()
        admin_ids = os.getenv("TELEGRAM_ADMIN_IDS", "").strip()
        self.TELEGRAM_ADMIN_IDS: Set[int] = {
            int(x) for x in admin_ids.replace(" ", "").split(",") if x.isdigit()
        } if admin_ids else set()

        # ── HTTP Client ───────────────────────────────────────────────────────
        self.HTTP_MAX_CONNECTIONS = 500
        self.HTTP_MAX_KEEPALIVE = 100
        self.HTTP_TIMEOUT = 30.0
        self.HTTP_CONNECT_TIMEOUT = 10.0

        # ── Logging & Monitoring ──────────────────────────────────────────────
        self.LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO").upper()
        self.LOG_FORMAT = "%(asctime)s [%(levelname)s] %(name)s: %(message)s"

        # Traffic accounting
        self.TRAFFIC_WRITE_THRESHOLD_MB = 10  # Write to DB every 10 MB
        self.TRAFFIC_WRITE_INTERVAL_SEC = 60  # Or every 60 seconds
        self.REQUEST_WRITE_INTERVAL_SEC = 60

        # ── Persistence ───────────────────────────────────────────────────────
        self.STATE_SAVE_INTERVAL = 5  # seconds (debounced)

    def _load_or_create_secret(self) -> str:
        """Load SECRET_KEY from file or create new one."""
        try:
            if self.SECRET_FILE.exists():
                existing = self.SECRET_FILE.read_text(encoding="utf-8").strip()
                if existing:
                    return existing
        except Exception:
            pass

        import secrets
        new_secret = secrets.token_urlsafe(32)
        try:
            self.SECRET_FILE.write_text(new_secret, encoding="utf-8")
        except Exception:
            pass  # If we can't persist, at least we have a secret for this run
        return new_secret

    @property
    def base_url(self) -> str:
        """Base URL for generating links."""
        if self.PUBLIC_DOMAIN:
            return f"https://{self.PUBLIC_DOMAIN}"
        return f"http://{self.HOST}:{self.PORT}"

    def get_host(self, request_host: Optional[str] = None) -> str:
        """Get the actual host from request or fallback."""
        if request_host:
            return request_host.split(":")[0]
        return self.PUBLIC_DOMAIN or "localhost"

    def to_dict(self) -> dict:
        """Export safe settings for frontend/templates."""
        return {
            "app_name": self.APP_NAME,
            "version": self.APP_VERSION,
            "protocols": list(self.PROTOCOLS),
            "transports": list(self.TRANSPORTS),
            "fingerprints": list(self.FINGERPRINTS),
            "default_fingerprint": self.DEFAULT_FINGERPRINT,
            "default_port": self.DEFAULT_PORT,
            "min_port": self.MIN_PORT,
            "max_port": self.MAX_PORT,
            "tls_ports": list(self.TLS_PORTS),
            "non_tls_ports": list(self.NON_TLS_PORTS),
        }


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Cached settings singleton."""
    return Settings()


settings = get_settings()