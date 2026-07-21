"""
MaKeVaslim Panel - Transport Implementations
All transport protocols: WS, HTTP/2, gRPC, XHTTP, QUIC, TCP
"""
import asyncio
import secrets
import socket
import time
import base64
import struct
from abc import ABC, abstractmethod
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from typing import Optional, Dict, Any, AsyncGenerator, Tuple, List
from collections import deque

import httpx
from fastapi import Request, WebSocket, WebSocketDisconnect, HTTPException
from fastapi.responses import StreamingResponse, Response

from ..config import settings
from ..database import get_db, DatabaseManager
from ..protocols import generate_vless, ProtocolConfig
from ..limits import throttle, reset_bucket


# ═══════════════════════════════════════════════════════════════════════════════
# Common Utilities
# ══════════════════════════════════════════════════════════════════════════════

RELAY_BUF = 256 * 1024  # 256 KB
TCP_NODELAY = True

# Connection tracking
connections: Dict[str, Dict[str, Any]] = {}
CONNECTIONS_LOCK = asyncio.Lock()


def get_client_ip(request: Request) -> str:
    """Extract real client IP considering proxies."""
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",")[0].strip()
    real_ip = request.headers.get("x-real-ip")
    if real_ip:
        return real_ip.strip()
    return request.client.host if request.client else "unknown"


async def parse_vless_header(data: bytes) -> Tuple[int, str, int, bytes]:
    """Parse VLESS header from first packet.
    Returns: (command, address, port, remaining_payload)
    """
    if len(data) < 24:
        raise ValueError("Packet too small for VLESS header")

    pos = 1  # Skip version byte
    pos += 16  # Skip UUID (16 bytes)

    # Addon length
    addon_len = data[pos]
    pos += 1 + addon_len

    command = data[pos]
    pos += 1

    port = struct.unpack(">H", data[pos:pos+2])[0]
    pos += 2

    addr_type = data[pos]
    pos += 1

    if addr_type == 1:  # IPv4
        address = ".".join(str(b) for b in data[pos:pos+4])
        pos += 4
    elif addr_type == 2:  # Domain
        dlen = data[pos]
        pos += 1
        address = data[pos:pos+dlen].decode("utf-8", errors="ignore")
        pos += dlen
    elif addr_type == 3:  # IPv6
        raw = data[pos:pos+16]
        address = ":".join(f"{raw[i]:02x}{raw[i+1]:02x}" for i in range(0, 16, 2))
        pos += 16
    else:
        raise ValueError(f"Unknown address type: {addr_type}")

    return command, address, port, data[pos:]


async def check_quota(uuid: str, bytes_count: int, db: DatabaseManager) -> bool:
    """Check and consume user quota."""
    if bytes_count <= 0:
        return True

    async with db.connection() as conn:
        cursor = await conn.execute(
            "SELECT used_gb, limit_gb, limit_req, used_req, is_active FROM users WHERE uuid = ?",
            (uuid,)
        )
        row = await cursor.fetchone()

    if not row or row["is_active"] == 0:
        return False

    # Check volume quota
    if row["limit_gb"] > 0:
        used_gb = row["used_gb"] + bytes_count / (1024**3)
        if used_gb >= row["limit_gb"]:
            return False

    # Check request quota
    if row["limit_req"] > 0 and row["used_req"] >= row["limit_req"]:
        return False

    # Update counters atomically
    gb_increment = bytes_count / (1024**3)
    await db.execute("""
        UPDATE users SET used_gb = used_gb + ?, used_req = used_req + 1 WHERE uuid = ?
    """, (gb_increment, uuid))

    return True


def tune_socket(writer: asyncio.StreamWriter):
    """Optimize socket for high throughput."""
    sock = writer.transport.get_extra_info("socket")
    if not sock:
        return
    try:
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 2 * 1024 * 1024)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 2 * 1024 * 1024)
    except OSError:
        pass


# ════════════════════════════════════════════════════════════════════════════════
# Base Transport Class
# ═══════════════════════════════════════════════════════════════════════════════

class BaseTransport(ABC):
    """Base class for all transports."""

    def __init__(self, name: str):
        self.name = name
        self.active_connections: Dict[str, Dict] = {}

    @abstractmethod
    async def handle_upstream(self, request: Request, uuid: str, session_id: str) -> Response:
        """Handle client → server (uplink)."""
        pass

    @abstractmethod
    async def handle_downstream(self, uuid: str, session_id: str) -> StreamingResponse:
        """Handle server → client (downlink)."""
        pass

    @abstractmethod
    async def handle_websocket(self, ws: WebSocket, uuid: str, session_id: str):
        """Handle WebSocket connection."""
        pass

    async def create_session(self, uuid: str, session_id: str, ip: str) -> Dict:
        """Create transport session record."""
        conn_id = secrets.token_urlsafe(8)
        session = {
            "id": conn_id,
            "uuid": uuid,
            "session_id": session_id,
            "ip": ip,
            "transport": self.name,
            "connected_at": time.time(),
            "bytes_up": 0,
            "bytes_down": 0,
            "writer": None,
            "reader": None,
            "closed": False,
        }

        async with CONNECTIONS_LOCK:
            connections[conn_id] = session
            self.active_connections[conn_id] = session

        return session

    async def close_session(self, conn_id: str):
        """Close and cleanup session."""
        async with CONNECTIONS_LOCK:
            session = connections.pop(conn_id, None)
            self.active_connections.pop(conn_id, None)

        if session:
            session["closed"] = True
            if session.get("writer"):
                try:
                    session["writer"].close()
                    await session["writer"].wait_closed()
                except Exception:
                    pass


# ═════════════════════════════════════════════════════════════════════════════════
# WebSocket Transport (VLESS over WS)
# ═══════════════════════════════════════════════════════════════════════════════

class WSTransport(BaseTransport):
    """VLESS over WebSocket transport."""

    def __init__(self):
        super().__init__("ws")

    async def handle_websocket(self, ws: WebSocket, uuid: str, session_id: str):
        """Main WebSocket handler for VLESS/WS."""
        await ws.accept()

        ip = get_client_ip(ws)
        session = await self.create_session(uuid, session_id, ip)

        try:
            # Receive first packet (contains VLESS header)
            first_msg = await asyncio.wait_for(ws.receive(), timeout=15.0)
            if first_msg["type"] == "websocket.disconnect":
                return

            first_data = first_msg.get("bytes") or (first_msg.get("text", "")).encode()
            if not first_data:
                await ws.close(code=1008, reason="Empty first packet")
                return

            # Parse VLESS header
            try:
                command, address, port, payload = await parse_vless_header(first_data)
            except Exception as e:
                await ws.close(code=1008, reason=f"Invalid VLESS header: {e}")
                return

            # Check quota for first packet
            db = await get_db()
            if not await check_quota(uuid, len(first_data), db):
                await ws.close(code=1008, reason="Quota exceeded")
                return

            # Connect to target
            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(address, port),
                    timeout=10.0
                )
                tune_socket(writer)
            except Exception as e:
                await ws.close(code=1008, reason=f"Connection failed: {e}")
                return

            # Send response header
            resp_header = bytes([first_data[0], 0])  # Version + success
            if payload:
                writer.write(payload)
                await writer.drain()

            # Update session
            session["writer"] = writer
            session["reader"] = reader
            session["target"] = f"{address}:{port}"

            # Start bidirectional relay
            await asyncio.gather(
                self._ws_to_tcp(ws, writer, session),
                self._tcp_to_ws(ws, reader, session),
            )

        except WebSocketDisconnect:
            pass
        except asyncio.TimeoutError:
            pass
        except Exception as e:
            print(f"WS error: {e}")
        finally:
            await self.close_session(session["id"])

    async def _ws_to_tcp(self, ws: WebSocket, writer: asyncio.StreamWriter, session: dict):
        """Relay WebSocket → TCP."""
        try:
            while True:
                msg = await ws.receive()
                if msg["type"] == "websocket.disconnect":
                    break

                data = msg.get("bytes") or (msg.get("text", "")).encode()
                if not data:
                    continue

                if not await check_quota(session["uuid"], len(data)):
                    await ws.close(code=1008, reason="Quota exceeded")
                    break

                await throttle(session["uuid"], len(data))

                writer.write(data)
                if writer.transport.get_write_buffer_size() > RELAY_BUF:
                    await writer.drain()

                session["bytes_up"] += len(data)

        except (WebSocketDisconnect, Exception):
            pass
        finally:
            try:
                writer.write_eof()
            except Exception:
                pass

    async def _tcp_to_ws(self, ws: WebSocket, reader: asyncio.StreamReader, session: dict):
        """Relay TCP → WebSocket."""
        first = True
        try:
            while True:
                data = await reader.read(RELAY_BUF)
                if not data:
                    break

                session["bytes_down"] += len(data)

                # VLESS response format: first packet has 2-byte header
                payload = (b"\x00\x00" + data) if first else data
                first = False

                await ws.send_bytes(payload)
        except Exception:
            pass

    # ─── Abstract method implementations ────────────────────────────────────────
    async def handle_upstream(self, request: Request, uuid: str, session_id: str):
        """WS transport uses WebSocket for upstream - not HTTP."""
        raise NotImplementedError("WS transport uses WebSocket, not HTTP upstream")

    async def handle_downstream(self, uuid: str, session_id: str) -> StreamingResponse:
        """WS transport uses WebSocket for downstream - not HTTP."""
        raise NotImplementedError("WS transport uses WebSocket, not HTTP downstream")


# ════════════════════════════════════════════════════════════════════════════════
# XHTTP Transport (Siz10a Ultra)
# ═══════════════════════════════════════════════════════════════════════════════

# XHTTP modes
XHTTP_MODES = ("packet-up", "stream-up", "stream-one")

# Adaptive flow control for stream-up
class AdaptiveFlow:
    """AIMD-style adaptive high-water mark for backpressure."""

    def __init__(self):
        self.high_water = 2 * 1024 * 1024  # 2 MB start
        self.min_hw = 256 * 1024
        self.max_hw = 16 * 1024 * 1024
        self.fast_drain_ms = 2.0
        self.slow_drain_ms = 25.0

    def should_drain(self, buffer_size: int) -> bool:
        return buffer_size > self.high_water

    async def drain(self, writer: asyncio.StreamWriter):
        """Drain with timing for AIMD."""
        start = time.monotonic()
        await writer.drain()
        elapsed_ms = (time.monotonic() - start) * 1000

        if elapsed_ms < self.fast_drain_ms:
            # Fast drain - increase high water (additive increase)
            self.high_water = min(self.max_hw, int(self.high_water * 1.5) + 65536)
        elif elapsed_ms > self.slow_drain_ms:
            # Slow drain - backpressure! (multiplicative decrease)
            self.high_water = max(self.min_hw, self.high_water // 2)


class AdaptiveQuotaGate:
    """Adaptive batch sizing for quota checking based on real throughput."""

    def __init__(self, uuid: str):
        self.uuid = uuid
        self.pending = 0
        self.last_check = time.monotonic()
        self.ok = True
        self.batch_bytes = 64 * 1024      # Start at 64 KB
        self.min_batch = 32 * 1024        # 32 KB minimum
        self.max_batch = 1 * 1024 * 1024  # 1 MB maximum
        self.rate_ewma = 0.0              # Exponential weighted moving average
        self.check_interval = 0.2         # Max time between checks (200ms)

    async def add(self, nbytes: int, check_func) -> bool:
        """Add bytes to pending, check quota if batch full or interval exceeded."""
        if not self.ok:
            return False

        self.pending += nbytes
        now = time.monotonic()
        elapsed = now - self.last_check

        # Check if batch threshold reached or time interval exceeded
        if self.pending >= self.batch_bytes or elapsed >= 0.2:
            flush = self.pending
            self.pending = 0
            self.last_check = now

            if elapsed > 0:
                inst_rate = flush / elapsed
                if self.rate_ewma == 0:
                    self.rate_ewma = inst_rate
                else:
                    # EWMA with alpha=0.3
                    self.rate_ewma = 0.7 * self.rate_ewma + 0.3 * inst_rate

                # Target batch = 200ms worth of data at current rate
                target = int(self.rate_ewma * 0.2)
                self.batch_bytes = max(
                    32 * 1024,
                    min(1024 * 1024, target or 32 * 1024)
                )

            # Actual quota check (calls DB)
            self.ok = await check_func(self.uuid, flush)
            return self.ok

        return True

    async def flush(self) -> bool:
        """Flush remaining pending bytes."""
        if self.pending:
            flush = self.pending
            self.pending = 0
            self.ok = self.ok and await check_func(self.uuid, flush)
        return self.ok


class XHTTPTransport(BaseTransport):
    """Siz10a XHTTP Ultra Transport - 3 modes."""

    def __init__(self, mode: str):
        if mode not in XHTTP_MODES:
            raise ValueError(f"Invalid XHTTP mode: {mode}")
        super().__init__(f"xhttp-{mode}")
        self.mode = mode
        self.sessions: Dict[str, Dict] = {}
        self._lock = asyncio.Lock()

    async def handle_downlink(self, uuid: str, session_id: str) -> StreamingResponse:
        """GET /xhttp/{mode}/{uuid}/{session_id} - Downlink (server → client)."""
        db = await get_db()
        user = await db.get_user_by_uuid(uuid)
        if not user or not user.is_allowed():
            raise HTTPException(403, "Not authorized")

        # Create or get session
        async with self._lock:
            session = self.sessions.get(session_id)
            if not session:
                session = {
                    "uuid": uuid,
                    "id": session_id,
                    "mode": self.mode,
                    "queue": asyncio.Queue(maxsize=512),
                    "queue_bytes": 0,
                    "closed": False,
                    "gate": None,
                    "flow": None,
                    "writer": None,
                    "tcp_connected": False,
                    "first_chunk": None,
                }
                self.sessions[session_id] = session

            # Initialize adaptive components for stream-up
            if self.mode == "stream-up":
                if session.get("gate") is None:
                    session["gate"] = AdaptiveQuotaGate(uuid)
                if session.get("flow") is None:
                    session["flow"] = AdaptiveFlow()

        # Fingerprint headers
        fp = "chrome"  # Default
        headers = {
            "content-type": "application/grpc",
            "cache-control": "no-cache, no-store",
            "x-accel-buffering": "no",
            "server": "cloudflare",
        }

        async def downlink_generator():
            try:
                while True:
                    chunk = await session["queue"].get()
                    if chunk is None:
                        break
                    session["queue_bytes"] -= len(chunk)
                    yield chunk
            except Exception:
                pass

        return StreamingResponse(
            downlink_generator(),
            headers=headers,
            media_type="application/grpc",
        )

    async def handle_uplink(self, request: Request, uuid: str, session_id: str) -> Response:
        """POST /xhttp/{mode}/{uuid}/{session_id}[/{seq}] - Uplink (client → server)."""
        db = await get_db()
        user = await db.get_user_by_uuid(uuid)
        if not user or not user.is_allowed():
            raise HTTPException(403, "Not authorized")

        async with self._lock:
            session = self.sessions.get(session_id)
            if not session:
                # Session will be created on downlink, but handle if uplink comes first
                session = {
                    "uuid": uuid,
                    "id": session_id,
                    "mode": self.mode,
                    "queue": asyncio.Queue(maxsize=512),
                    "queue_bytes": 0,
                    "closed": False,
                    "writer": None,
                    "tcp_connected": False,
                    "seq_buf": {},
                    "next_seq": 0,
                }
                self.sessions[session_id] = session

            if self.mode == "stream-up":
                if session.get("gate") is None:
                    session["gate"] = AdaptiveQuotaGate(uuid)
                if session.get("flow") is None:
                    session["flow"] = AdaptiveFlow()

        gate = session.get("gate")
        flow = session.get("flow")

        body = await request.body()
        if not body:
            return {"ok": True}

        # Check quota
        if gate and not await gate.add(len(body)):
            raise HTTPException(403, "Quota exceeded")
        await throttle(uuid, len(body))

        # Handle different modes
        if self.mode == "packet-up":
            return await self._handle_packet_up(session, body)
        elif self.mode == "stream-up":
            return await self._handle_stream_up(session, body, flow)
        elif self.mode == "stream-one":
            return await self._handle_stream_one(session, body)

        return {"ok": True}

    async def _handle_packet_up(self, session: dict, body: bytes) -> dict:
        """Packet-up: each POST is a packet with sequence number."""
        # First packet contains VLESS header
        if session.get("writer") is None:
            # Parse VLESS header
            try:
                command, address, port, payload = await parse_vless_header(body)
            except Exception as e:
                raise HTTPException(400, f"Invalid VLESS header: {e}")

            # Check quota for header
            if not await check_quota(session["uuid"], len(body)):
                raise HTTPException(403, "Quota exceeded")

            # Connect to target
            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(address, port),
                    timeout=10.0
                )
                tune_socket(writer)
            except Exception as e:
                raise HTTPException(502, f"Connection failed: {e}")

            session["writer"] = writer
            session["reader"] = reader
            session["tcp_connected"] = True

            # Send payload if any
            if payload:
                writer.write(payload)
                await writer.drain()

            # Start downlink pump
            asyncio.create_task(self._pump_tcp_to_queue(session))

            return {"ok": True, "connected": True}

        # Subsequent packets - direct write
        if session.get("writer"):
            session["writer"].write(body)
            if session["writer"].transport.get_write_buffer_size() > RELAY_BUF:
                await session["writer"].drain()
            return {"ok": True}

        raise HTTPException(400, "No connection established")

    async def _handle_stream_up(self, session: dict, body: bytes, flow: AdaptiveFlow) -> dict:
        """Stream-up: continuous stream with adaptive flow control."""
        if session.get("writer") is None:
            # First chunk contains VLESS header
            try:
                command, address, port, payload = await parse_vless_header(body)
            except Exception as e:
                raise HTTPException(400, f"Invalid VLESS header: {e}")

            if not await check_quota(session["uuid"], len(body)):
                raise HTTPException(403, "Quota exceeded")

            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(address, port),
                    timeout=10.0
                )
                tune_socket(writer)
            except Exception as e:
                raise HTTPException(502, f"Connection failed: {e}")

            session["writer"] = writer
            session["reader"] = reader
            session["tcp_connected"] = True

            # Send initial payload
            if payload:
                writer.write(payload)

            # Start downlink pump with adaptive quota gate
            asyncio.create_task(self._pump_tcp_to_queue_adaptive(session))

        # Write chunk
        writer = session["writer"]
        writer.write(body)

        # Adaptive drain based on buffer pressure
        if flow and flow.should_drain(writer.transport.get_write_buffer_size()):
            await flow.drain(writer)

        return {"ok": True}

    async def _handle_stream_one(self, session: dict, body: bytes) -> dict:
        """Stream-one: single long-lived stream (simplified stream-up)."""
        # Similar to stream-up but without adaptive flow
        if session.get("writer") is None:
            try:
                command, address, port, payload = await parse_vless_header(body)
            except Exception as e:
                raise HTTPException(400, f"Invalid VLESS header: {e}")

            if not await check_quota(session["uuid"], len(body)):
                raise HTTPException(403, "Quota exceeded")

            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(address, port),
                    timeout=10.0
                )
                tune_socket(writer)
            except Exception as e:
                raise HTTPException(502, f"Connection failed: {e}")

            session["writer"] = writer
            session["reader"] = reader

            if payload:
                writer.write(payload)
                await writer.drain()

            asyncio.create_task(self._pump_tcp_to_queue(session))

        else:
            session["writer"].write(body)
            if session["writer"].transport.get_write_buffer_size() > RELAY_BUF:
                await session["writer"].drain()

        return {"ok": True}

    async def _pump_tcp_to_queue(self, session: dict):
        """Pump TCP reader → downlink queue (basic)."""
        reader = session.get("reader")
        queue = session.get("queue")
        if not reader or not queue:
            return

        first = True
        try:
            while True:
                data = await reader.read(RELAY_BUF)
                if not data:
                    break

                if first:
                    data = b"\x00\x00" + data
                    first = False

                await queue.put(data)
        except Exception:
            pass
        finally:
            await queue.put(None)  # Signal end

    async def _pump_tcp_to_queue_adaptive(self, session: dict):
        """Pump TCP reader → downlink queue with adaptive quota gate."""
        reader = session.get("reader")
        queue = session.get("queue")
        gate = session.get("gate")
        if not reader or not queue or not gate:
            return

        first = True
        try:
            while True:
                data = await reader.read(RELAY_BUF)
                if not data:
                    break

                if first:
                    data = b"\x00\x00" + data
                    first = False

                # Check quota for downlink too
                if not await gate.add(len(data)):
                    break

                await queue.put(data)
        except Exception:
            pass
        finally:
            await gate.flush()
            await queue.put(None)

    # ─── Abstract method implementations ────────────────────────────────────────
    async def handle_upstream(self, request: Request, uuid: str, session_id: str):
        """Delegate to handle_uplink (POST /xhttp/...)."""
        return await self.handle_uplink(request, uuid, session_id)

    async def handle_downstream(self, uuid: str, session_id: str) -> StreamingResponse:
        """Delegate to handle_downlink (GET /xhttp/...)."""
        return await self.handle_downlink(uuid, session_id)

    async def handle_websocket(self, ws: WebSocket, uuid: str, session_id: str):
        """XHTTP does not use WebSocket - raise NotImplementedError."""
        raise NotImplementedError("XHTTP transport does not support WebSocket")


# ════════════════════════════════════════════════════════════════════════════════
# HTTP/2 Transport
# ═══════════════════════════════════════════════════════════════════════════════

class H2Transport(BaseTransport):
    """VLESS over HTTP/2 (h2) transport."""

    def __init__(self):
        super().__init__("h2")
        self.streams: Dict[int, Dict] = {}

    async def handle_upstream(self, request: Request, uuid: str, session_id: str) -> Response:
        # HTTP/2 uses stream multiplexing
        pass

    async def handle_downstream(self, uuid: str, session_id: str) -> StreamingResponse:
        pass

    async def handle_websocket(self, ws: WebSocket, uuid: str, session_id: str):
        # h2 doesn't use WebSocket, uses HTTP/2 streams
        pass


# ════════════════════════════════════════════════════════════════════════════════
# gRPC Transport
# ═══════════════════════════════════════════════════════════════════════════════

class GRPCTransport(BaseTransport):
    """VLESS over gRPC transport."""

    def __init__(self):
        super().__init__("grpc")
        self.service_name = "GunService"

    async def handle_upstream(self, request: Request, uuid: str, session_id: str) -> Response:
        # gRPC unary or streaming
        pass

    async def handle_downstream(self, uuid: str, session_id: str) -> StreamingResponse:
        pass

    async def handle_websocket(self, ws: WebSocket, uuid: str, session_id: str):
        # gRPC doesn't use WebSocket, uses HTTP/2 streams
        pass


# ══════════════════════════════════════════════════════════════════════════════
# QUIC Transport (Hysteria2, TUIC)
# ═════════════════════════════════════════════════════════════════════════════

class QUICTransport(BaseTransport):
    """QUIC-based transports (Hysteria2, TUIC)."""

    def __init__(self, protocol: str):
        super().__init__(protocol)
        self.protocol = protocol  # "hysteria2" or "tuic"

    async def handle_upstream(self, request: Request, uuid: str, session_id: str) -> Response:
        # QUIC uses different handling
        pass

    async def handle_downstream(self, uuid: str, session_id: str) -> StreamingResponse:
        pass

    async def handle_websocket(self, ws: WebSocket, uuid: str, session_id: str):
        pass


# ═══════════════════════════════════════════════════════════════════════════════
# TCP Raw Transport
# ══════════════════════════════════════════════════════════════════════════════

class TCPTransport(BaseTransport):
    """Raw TCP transport (for Trojan, Shadowsocks, etc.)."""

    def __init__(self):
        super().__init__("tcp")

    async def handle_websocket(self, ws: WebSocket, uuid: str, session_id: str):
        # TCP doesn't use WebSocket
        pass


# ══════════════════════════════════════════════════════════════════════════════
# Transport Registry & Factory
# ═══════════════════════════════════════════════════════════════════════════════

_transport_instances: Dict[str, BaseTransport] = {}


def get_transport(name: str) -> BaseTransport:
    """Get or create transport instance."""
    if name in _transport_instances:
        return _transport_instances[name]

    if name == "ws":
        instance = WSTransport()
    elif name.startswith("xhttp-"):
        mode = name.split("-", 1)[1]
        instance = XHTTPTransport(mode)
    elif name == "h2":
        instance = H2Transport()
    elif name == "grpc":
        instance = GRPCTransport()
    elif name in ("hysteria2", "tuic"):
        instance = QUICTransport(name)
    elif name == "tcp":
        instance = TCPTransport()
    else:
        raise ValueError(f"Unknown transport: {name}")

    _transport_instances[name] = instance
    return instance


def get_all_transports() -> List[BaseTransport]:
    """Get all transport instances."""
    return list(_transport_instances.values())


async def cleanup_all_transports():
    """Close all transport connections."""
    for transport in _transport_instances.values():
        for conn_id in list(transport.active_connections.keys()):
            await transport.close_session(conn_id)


# ═════════════════════════════════════════════════════════════════════════════════
# Connection Relay Helpers (for VLESS/WS)
# ════════════════════════════════════════════════════════════════════════════════

async def relay_ws_to_tcp(
    ws: WebSocket,
    writer: asyncio.StreamWriter,
    session: dict,
    db: DatabaseManager
):
    """Relay WebSocket → TCP with quota and speed limiting."""
    try:
        while True:
            msg = await ws.receive()
            if msg["type"] == "websocket.disconnect":
                break

            data = msg.get("bytes") or (msg.get("text", "")).encode()
            if not data:
                continue

            if not await check_quota(session["uuid"], len(data), db):
                await ws.close(code=1008, reason="Quota exceeded")
                break

            await throttle(session["uuid"], len(data))

            writer.write(data)
            if writer.transport.get_write_buffer_size() > RELAY_BUF:
                await writer.drain()

            session["bytes_up"] = session.get("bytes_up", 0) + len(data)

    except (WebSocketDisconnect, Exception):
        pass
    finally:
        try:
            writer.write_eof()
        except Exception:
            pass


async def relay_tcp_to_ws(
    ws: WebSocket,
    reader: asyncio.StreamReader,
    session: dict
):
    """Relay TCP → WebSocket."""
    first = True
    try:
        while True:
            data = await reader.read(RELAY_BUF)
            if not data:
                break

            payload = (b"\x00\x00" + data) if first else data
            first = False
            await ws.send_bytes(payload)
    except Exception:
        pass


async def open_tcp_connection(address: str, port: int, initial_data: bytes = b"") -> Tuple[asyncio.StreamReader, asyncio.StreamWriter]:
    """Open TCP connection with optimized socket."""
    reader, writer = await asyncio.wait_for(
        asyncio.open_connection(address, port),
        timeout=10.0
    )
    tune_socket(writer)

    if initial_data:
        writer.write(initial_data)
        await writer.drain()

    return reader, writer


# ═══════════════════════════════════════════════════════════════════════════════════════════════════════════════════════
# Exports
# ══════════════════════════════════════════════════════════════════════════════════════════════════════════════════════

__all__ = [
    "BaseTransport",
    "WSTransport",
    "XHTTPTransport",
    "XHTTP_MODES",
    "AdaptiveFlow",
    "AdaptiveQuotaGate",
    "H2Transport",
    "GRPCTransport",
    "QUICTransport",
    "TCPTransport",
    "get_transport",
    "get_all_transports",
    "cleanup_all_transports",
    "RELAY_BUF",
    "parse_vless_header",
    "check_quota",
    "get_client_ip",
    "tune_socket",
    "relay_ws_to_tcp",
    "relay_tcp_to_ws",
    "open_tcp_connection",
]