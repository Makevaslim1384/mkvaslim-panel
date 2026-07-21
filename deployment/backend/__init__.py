"""
MaKeVaslim Panel - Backend Package
"""
__version__ = "1.0.0"
__author__ = "MaKeVaslim Team"
__email__ = "support@makevaslim.com"

from .config import settings
from .database import DatabaseManager, get_db, close_db, User
from .auth import (
    get_current_user,
    require_auth,
    require_admin,
    login_user,
    logout_user,
    hash_password,
    verify_password,
)
from .protocols import (
    generate_vless,
    generate_vmess,
    generate_trojan,
    generate_shadowsocks,
    generate_hysteria2,
    generate_tuic,
    generate_all_links,
    ProtocolConfig,
)
from .transports import (
    get_transport,
    get_all_transports,
    WSTransport,
    XHTTPTransport,
    XHTTP_MODES,
)
from .limits import (
    throttle_user,
    throttle_connection,
    AdaptiveQuotaGate,
    AdaptiveFlow,
    parse_speed_limit,
    format_speed,
    record_traffic,
    get_hourly_traffic,
)

__all__ = [
    "settings",
    "DatabaseManager",
    "get_db",
    "close_db",
    "User",
    "get_current_user",
    "require_auth",
    "require_admin",
    "login_user",
    "logout_user",
    "hash_password",
    "verify_password",
    "generate_vless",
    "generate_vmess",
    "generate_trojan",
    "generate_shadowsocks",
    "generate_hysteria2",
    "generate_tuic",
    "generate_all_links",
    "ProtocolConfig",
    "get_transport",
    "get_all_transports",
    "WSTransport",
    "XHTTPTransport",
    "XHTTP_MODES",
    "throttle_user",
    "throttle_connection",
    "AdaptiveQuotaGate",
    "AdaptiveFlow",
    "parse_speed_limit",
    "format_speed",
    "record_traffic",
    "get_hourly_traffic",
]