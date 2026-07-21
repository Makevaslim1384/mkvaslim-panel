"""
MaKeVaslim Panel - Protocol Link Generators
Generate connection links for all supported protocols.
"""
from __future__ import annotations
import urllib.parse
from dataclasses import dataclass
from typing import Optional, Dict, List, Any
from .config import settings


# ════════════════════════════════════════════════════════════════════════════════
# Base Classes
# ═══════════════════════════════════════════════════════════════════════════════

@dataclass
class ProtocolConfig:
    """Configuration for generating a protocol link."""
    uuid: str
    host: str
    port: int
    remark: str
    transport: str = "ws"
    fingerprint: str = "chrome"
    alpn: str = ""
    sni: str = ""
    path: str = ""
    host_header: str = ""
    security: str = "tls"
    encryption: str = "none"
    flow: str = ""
    pbk: str = ""      # Reality public key
    sid: str = ""      # Reality short ID
    spx: str = ""      # Reality spiderX
    type: str = ""     # Header type for HTTP
    host_list: str = ""  # Comma-separated hosts
    seed: str = ""     # TUIC seed
    congestion: str = ""  # TUIC congestion control
    # Hysteria2 specific
    obfs: str = ""
    obfs_password: str = ""
    # TUIC specific
    alpn_list: str = "h3,h2,http/1.1"
    # WireGuard
    private_key: str = ""
    public_key: str = ""
    preshared_key: str = ""
    allowed_ips: str = "0.0.0.0/0,::/0"
    endpoint: str = ""
    keepalive: int = 25


def quote_param(value: str) -> str:
    """URL encode parameter value."""
    return urllib.parse.quote(str(value), safe="")


def build_query(params: Dict[str, str]) -> str:
    """Build query string from dict, skipping empty values."""
    filtered = {k: v for k, v in params.items() if v not in (None, "", 0, False)}
    return "&".join(f"{k}={quote_param(v)}" for k, v in filtered.items())


def build_link(scheme: str, userinfo: str, host: str, port: int, query: str, fragment: str) -> str:
    """Build standard URI link."""
    return f"{scheme}://{userinfo}@{host}:{port}?{query}#{quote_param(fragment)}"


# ════════════════════════════════════════════════════════════════════════════════
# VLESS Generator
# ════════════════════════════════════════════════════════════════════════════════

def generate_vless(config: ProtocolConfig) -> str:
    """Generate VLESS connection link."""
    params = {
        "encryption": config.encryption,
        "security": config.security,
        "type": config.transport,
        "fp": config.fingerprint,
    }

    if config.transport == "ws":
        params.update({
            "host": config.host_header or config.host,
            "path": config.path or "/",
            "sni": config.sni or config.host,
        })
        if config.alpn:
            params["alpn"] = config.alpn

    elif config.transport == "h2":
        params.update({
            "host": config.host_header or config.host,
            "path": config.path or "/",
            "sni": config.sni or config.host,
        })
        if config.alpn:
            params["alpn"] = config.alpn

    elif config.transport == "grpc":
        params.update({
            "serviceName": config.path or "GunService",
            "sni": config.sni or config.host,
        })
        if config.alpn:
            params["alpn"] = config.alpn

    elif config.transport == "xhttp":
        # XHTTP modes: packet-up, stream-up, stream-one
        params.update({
            "mode": config.path.split("/")[-1] if "/" in config.path else "packet-up",
            "host": config.host_header or config.host,
            "path": config.path or "/",
            "sni": config.sni or config.host,
        })
        if config.alpn:
            params["alpn"] = config.alpn

    elif config.transport == "tcp":
        if config.security == "reality":
            params.update({
                "pbk": config.pbk,
                "sid": config.sid,
                "spx": config.spx,
            })
        else:
            params.update({
                "headerType": config.type or "none",
                "host": config.host_list or config.host_header or config.host,
            })
        params["sni"] = config.sni or config.host

    elif config.transport == "quic":
        params.update({
            "security": config.security,
            "key": config.obfs_password or "",
            "headerType": config.type or "none",
        })

    # Common params
    if config.flow:
        params["flow"] = config.flow
    if config.alpn and config.transport not in ("ws", "h2", "grpc", "xhttp"):
        params["alpn"] = config.alpn

    userinfo = config.uuid
    query = build_query(params)
    return build_link("vless", userinfo, config.host, config.port, query, config.remark)


# ═════════════════════════════════════════════════════════════════════════════════
# VMess Generator
# ═══════════════════════════════════════════════════════════════════════════════

import base64
import json

def generate_vmess(config: ProtocolConfig) -> str:
    """Generate VMess connection link (Base64 JSON)."""
    vmess_obj = {
        "v": "2",
        "ps": config.remark,
        "add": config.host,
        "port": str(config.port),
        "id": config.uuid,
        "aid": "0",
        "scy": "auto",
        "net": config.transport,
        "type": "none",
        "host": config.host_header or config.host,
        "path": config.path or "/",
        "tls": config.security,
        "sni": config.sni or config.host,
        "fp": config.fingerprint,
        "alpn": config.alpn or "",
    }

    # Transport-specific fields
    if config.transport == "ws":
        vmess_obj["type"] = "none"
    elif config.transport == "h2":
        vmess_obj["type"] = "none"
    elif config.transport == "grpc":
        vmess_obj["serviceName"] = config.path or "GunService"
    elif config.transport == "tcp":
        vmess_obj["headerType"] = "none"

    if config.security == "tls":
        vmess_obj["tls"] = "tls"
    elif config.security == "reality":
        vmess_obj["tls"] = "tls"
        vmess_obj["reality"] = {
            "pbk": config.pbk,
            "sid": config.sid,
            "spx": config.spx,
        }

    json_str = json.dumps(vmess_obj, separators=(",", ":"))
    b64 = base64.b64encode(json_str.encode()).decode()
    return f"vmess://{b64}"


# ════════════════════════════════════════════════════════════════════════════════
# Trojan Generator
# ══════════════════════════════════════════════════════════════════════════════

def generate_trojan(config: ProtocolConfig) -> str:
    """Generate Trojan connection link."""
    params = {
        "security": config.security,
        "type": config.transport,
        "sni": config.sni or config.host,
        "fp": config.fingerprint,
        "allowInsecure": "1" if config.security == "none" else "0",
    }

    if config.transport == "ws":
        params.update({
            "type": "ws",
            "host": config.host_header or config.host,
            "path": config.path or "/",
        })
    elif config.transport == "h2":
        params.update({
            "type": "h2",
            "host": config.host_header or config.host,
            "path": config.path or "/",
        })
    elif config.transport == "grpc":
        params.update({
            "type": "grpc",
            "serviceName": config.path or "GunService",
        })
    elif config.transport == "tcp":
        params.update({
            "headerType": config.type or "none",
            "host": config.host_list or config.host_header or config.host,
        })

    if config.alpn:
        params["alpn"] = config.alpn

    userinfo = config.uuid
    query = build_query(params)
    return build_link("trojan", userinfo, config.host, config.port, query, config.remark)


# ════════════════════════════════════════════════════════════════════════════════
# Shadowsocks Generator
# ═════════════════════════════════════════════════════════════════════════════

def generate_shadowsocks(config: ProtocolConfig) -> str:
    """Generate Shadowsocks connection link."""
    # method:password@host:port
    # For SS, uuid is used as password, method defaults to 2022-blake3-aes-128-gcm
    method = "2022-blake3-aes-128-gcm"
    password = config.uuid

    userinfo = base64.b64encode(f"{method}:{password}".encode()).decode()
    params = {}

    if config.transport != "tcp":
        params["plugin"] = f"v2ray-plugin;mux=0;host={config.host_header or config.host};path={config.path or '/'};tls={1 if config.security == 'tls' else 0}"
        if config.security == "tls":
            params["plugin"] += f";sni={config.sni or config.host}"

    query = build_query(params)
    return build_link("ss", userinfo, config.host, config.port, query, config.remark)


# ══════════════════════════════════════════════════════════════════════════════
# Hysteria2 Generator
# ════════════════════════════════════════════════════════════════════════════

def generate_hysteria2(config: ProtocolConfig) -> str:
    """Generate Hysteria2 connection link."""
    # hysteria2://password@host:port?params
    params = {
        "security": "tls",
        "sni": config.sni or config.host,
        "fp": config.fingerprint,
        "alpn": config.alpn or "h3",
        "obfs": config.obfs or "none",
    }

    if config.obfs_password:
        params["obfs-password"] = config.obfs_password

    if config.insecure:
        params["insecure"] = "1"

    userinfo = config.uuid  # password
    query = build_query(params)
    return build_link("hysteria2", userinfo, config.host, config.port, query, config.remark)


# ══════════════════════════════════════════════════════════════════════════════
# TUIC Generator
# ═════════════════════════════════════════════════════════════════════════════

def generate_tuic(config: ProtocolConfig) -> str:
    """Generate TUIC connection link."""
    # tuic://uuid:password@host:port?params
    params = {
        "congestion_control": config.congestion or "bbr",
        "udp_relay_mode": "native",
        "alpn": config.alpn_list or "h3,h2,http/1.1",
        "reduce_rtt": "1",
        "heartbeat": "10s",
    }

    if config.seed:
        params["seed"] = config.seed

    # For TUIC v5, format is tuic://uuid:password@host:port
    userinfo = f"{config.uuid}:{config.uuid}"  # uuid as both user and password
    query = build_query(params)
    return build_link("tuic", userinfo, config.host, config.port, query, config.remark)


# ══════════════════════════════════════════════════════════════════════════════
# WireGuard Generator (Basic)
# ══════════════════════════════════════════════════════════════════════════════

def generate_wireguard(config: ProtocolConfig) -> str:
    """Generate WireGuard configuration (returns config text, not URI)."""
    # WireGuard doesn't use URI scheme, returns config file content
    lines = [
        "[Interface]",
        f"PrivateKey = {config.private_key}",
        f"Address = {config.allowed_ips}",
        f"DNS = 1.1.1.1, 8.8.8.8",
    ]

    if config.keepalive:
        lines.append(f"PersistentKeepalive = {config.keepalive}")

    lines.extend([
        "",
        "[Peer]",
        f"PublicKey = {config.public_key}",
        f"AllowedIPs = {config.allowed_ips}",
        f"Endpoint = {config.endpoint or f'{config.host}:{config.port}'}",
    ])

    if config.preshared_key:
        lines.append(f"PresharedKey = {config.preshared_key}")

    return "\n".join(lines)


# ════════════════════════════════════════════════════════════════════════════════
# Multi-Protocol Generator
# ═════════════════════════════════════════════════════════════════════════════

def generate_all_links(
    uuid: str,
    host: str,
    ports: List[int],
    remark: str,
    transport: str = "ws",
    fingerprint: str = "chrome",
    alpn: str = "",
    sni: str = "",
    path: str = "",
    host_header: str = "",
    security: str = "tls",
    flow: str = "",
    ips: str = "",
    max_ports: int = 10,
) -> Dict[str, List[str]]:
    """
    Generate links for all protocols across multiple ports.
    Returns dict: {protocol: [links]}
    """
    links = {}
    ports = ports[:max_ports]

    for port in ports:
        config = ProtocolConfig(
            uuid=uuid,
            host=host,
            port=port,
            remark=f"{remark} | {port}",
            transport=transport,
            fingerprint=fingerprint,
            alpn=alpn,
            sni=sni,
            path=path,
            host_header=host_header,
            security=security,
            flow=flow,
        )

        # VLESS (always supported)
        links.setdefault("vless", []).append(generate_vless(config))

        # VMess
        links.setdefault("vmess", []).append(generate_vmess(config))

        # Trojan
        links.setdefault("trojan", []).append(generate_trojan(config))

        # Shadowsocks (only on non-TLS ports typically)
        if port not in settings.TLS_PORTS or security == "none":
            links.setdefault("shadowsocks", []).append(generate_shadowsocks(config))

        # Hysteria2 (QUIC only)
        if port in settings.TLS_PORTS:
            links.setdefault("hysteria2", []).append(generate_hysteria2(config))

        # TUIC (QUIC only)
        if port in settings.TLS_PORTS:
            links.setdefault("tuic", []).append(generate_tuic(config))

    return links


def generate_subscription_text(links: List[str]) -> str:
    """Generate Base64 encoded subscription text."""
    import base64
    text = "\n".join(links)
    return base64.b64encode(text.encode()).decode()


# ═════════════════════════════════════════════════════════════════════════════════
# Export
# ════════════════════════════════════════════════════════════════════════════════

__all__ = [
    "ProtocolConfig",
    "generate_vless",
    "generate_vmess",
    "generate_trojan",
    "generate_shadowsocks",
    "generate_hysteria2",
    "generate_tuic",
    "generate_wireguard",
    "generate_all_links",
    "generate_subscription_text",
    "build_link",
    "quote_param",
]