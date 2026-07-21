"""
MaKeVaslim Panel - Rate Limiting & Traffic Control
Token Bucket speed limiting, Adaptive Quota Gates, AIMD Flow Control.
"""
import asyncio
import time
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Dict, Optional
from .config import settings


# ═══════════════════════════════════════════════════════════════════════════════
# Token Bucket Speed Limiter (Per-User/Per-Config)
# ═══════════════════════════════════════════════════════════════════════════════

@dataclass
class TokenBucket:
    """Token bucket for rate limiting."""
    rate: float           # bytes per second (refill rate)
    capacity: float       # maximum bucket size (burst allowance)
    tokens: float         # current tokens available
    last_refill: float    # last refill timestamp (monotonic)

    def __init__(self, rate_bps: float):
        self.rate = max(rate_bps, settings.MIN_SPEED_LIMIT)
        self.capacity = max(self.rate, 16 * 1024)  # Min 16 KB burst
        self.tokens = self.capacity
        self.last_refill = time.monotonic()

    def _refill(self):
        """Refill tokens based on elapsed time."""
        now = time.monotonic()
        elapsed = now - self.last_refill
        if elapsed > 0:
            self.last_refill = now
            self.tokens = min(self.capacity, self.tokens + elapsed * self.rate)

    async def consume(self, n: int) -> bool:
        """Try to consume n tokens. Returns True if successful, False if would block."""
        if n <= 0:
            return True

        self._refill()
        if self.tokens >= n:
            self.tokens -= n
            return True
        return False

    async def wait_consume(self, n: int) -> None:
        """Wait until n tokens are available, then consume them."""
        if n <= 0:
            return

        while True:
            self._refill()
            if self.tokens >= n:
                self.tokens -= n
                return

            deficit = n - self.tokens
            wait_time = deficit / self.rate
            # Cap wait time to avoid excessive blocking, but allow up to 0.5s
            await asyncio.sleep(min(max(wait_time, 0.004), 0.5))


# Global bucket registry (per UUID)
_buckets: Dict[str, TokenBucket] = {}
_buckets_lock = asyncio.Lock()


def get_bucket(uuid: str, rate_bps: float) -> TokenBucket:
    """Get or create token bucket for UUID with given rate."""
    if uuid not in _buckets or _buckets[uuid].rate != max(rate_bps, settings.MIN_SPEED_LIMIT):
        _buckets[uuid] = TokenBucket(rate_bps)
    return _buckets[uuid]


def reset_bucket(uuid: str):
    """Reset/remove bucket (call when config changes)."""
    _buckets.pop(uuid, None)


async def throttle(uuid: str, nbytes: int):
    """Throttle nbytes for given UUID. Blocks if rate limit exceeded."""
    if nbytes <= 0:
        return

    # Get user's speed limit from config (would need DB lookup in real use)
    # For now, we'll use a global or pass rate as parameter
    # This is called from transports with rate already known
    pass  # Implementation in transports uses bucket directly


# ═══════════════════════════════════════════════════════════════════════════════
# Adaptive Quota Gate (Batch-based Quota Checking)
# ═══════════════════════════════════════════════════════════════════════════════

class AdaptiveQuotaGate:
    """
    Adaptive quota checking that batches bytes to reduce DB writes.
    Batch size adapts to real-time throughput (EWMA).
    """

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

    async def flush(self, check_func) -> bool:
        """Flush remaining pending bytes."""
        if self.pending:
            flush = self.pending
            self.pending = 0
            self.ok = self.ok and await check_func(self.uuid, flush)
        return self.ok


# ═══════════════════════════════════════════════════════════════════════════════
# AIMD Flow Control (Adaptive High-Water Mark)
# ═══════════════════════════════════════════════════════════════════════════════

class AdaptiveFlow:
    """
    AIMD-style adaptive high-water mark for writer.drain() backpressure.
    Similar to TCP congestion control but for application-level buffering.
    """

    def __init__(self):
        self.high_water = 2 * 1024 * 1024      # Start at 2 MB
        self.min_hw = 256 * 1024               # 256 KB minimum
        self.max_hw = 16 * 1024 * 1024         # 16 MB maximum
        self.fast_drain_ms = 2.0               # Below this = fast drain
        self.slow_drain_ms = 25.0              # Above this = slow drain (backpressure)
        self.last_drain_ms = 0.0

    def should_drain(self, buffer_size: int) -> bool:
        """Check if buffer exceeds adaptive high-water mark."""
        return buffer_size > self.high_water

    async def drain(self, writer: asyncio.StreamWriter) -> float:
        """
        Drain writer buffer and adapt high-water mark based on drain time.
        Returns drain time in milliseconds.
        """
        start = time.monotonic()
        await writer.drain()
        elapsed_ms = (time.monotonic() - start) * 1000

        self.last_drain_ms = elapsed_ms

        if elapsed_ms < 2.0:  # Very fast drain
            # Network can handle more - additive increase
            self.high_water = min(
                self.max_hw,
                int(self.high_water * 1.5) + 65536
            )
        elif elapsed_ms > 25.0:  # Slow drain = backpressure
            # Multiplicative decrease
            self.high_water = max(self.min_hw, self.high_water // 2)

        return elapsed_ms


# ════════════════════════════════════════════════════════════════════════════════
# Connection-Level Rate Limiting (Per-Session)
# ═══════════════════════════════════════════════════════════════════════════════

@dataclass
class SessionRateLimiter:
    """Per-connection rate limiter with burst allowance."""
    rate_bps: float
    bucket: TokenBucket
    max_burst: int = 512 * 1024  # 512 KB max burst per connection

    def __init__(self, rate_bps: float):
        self.rate_bps = max(rate_bps, settings.MIN_SPEED_LIMIT)
        self.bucket = TokenBucket(self.rate_bps)
        # Increase capacity for connection-level burst
        self.bucket.capacity = max(self.bucket.capacity, self.max_burst)

    async def consume(self, nbytes: int) -> bool:
        return await self.bucket.consume(nbytes)

    async def wait_consume(self, nbytes: int):
        await self.bucket.wait_consume(nbytes)


# ═══════════════════════════════════════════════════════════════════════════════
# Global Rate Limit Manager
# ═══════════════════════════════════════════════════════════════════════════════

class RateLimitManager:
    """Centralized rate limit management."""

    def __init__(self):
        self.user_buckets: Dict[str, TokenBucket] = {}
        self.connection_limiters: Dict[str, SessionRateLimiter] = {}
        self._lock = asyncio.Lock()

    async def get_user_bucket(self, uuid: str, rate_bps: float) -> TokenBucket:
        """Get or create user's token bucket."""
        async with self._lock:
            if uuid not in self.user_buckets or self.user_buckets[uuid].rate != rate_bps:
                self.user_buckets[uuid] = TokenBucket(rate_bps)
            return self.user_buckets[uuid]

    async def get_connection_limiter(self, session_id: str, rate_bps: float) -> SessionRateLimiter:
        """Get or create connection-level limiter."""
        async with self._lock:
            if session_id not in self.connection_limiters:
                self.connection_limiters[session_id] = SessionRateLimiter(rate_bps)
            return self.connection_limiters[session_id]

    async def remove_connection(self, session_id: str):
        async with self._lock:
            self.connection_limiters.pop(session_id, None)

    async def reset_user(self, uuid: str):
        async with self._lock:
            self.user_buckets.pop(uuid, None)

    async def consume_user(self, uuid: str, nbytes: int, rate_bps: float) -> bool:
        """Try to consume from user's bucket (non-blocking)."""
        bucket = await self.get_user_bucket(uuid, rate_bps)
        return await bucket.consume(nbytes)

    async def wait_user(self, uuid: str, nbytes: int, rate_bps: float):
        """Wait and consume from user's bucket (blocking)."""
        bucket = await self.get_user_bucket(uuid, rate_bps)
        await bucket.wait_consume(nbytes)

    async def consume_connection(self, session_id: str, nbytes: int, rate_bps: float) -> bool:
        """Try to consume from connection's bucket."""
        limiter = await self.get_connection_limiter(session_id, rate_bps)
        return await limiter.consume(nbytes)

    async def wait_connection(self, session_id: str, nbytes: int, rate_bps: float):
        """Wait and consume from connection's bucket."""
        limiter = await self.get_connection_limiter(session_id, rate_bps)
        await limiter.wait_consume(nbytes)

    def get_user_stats(self, uuid: str) -> dict:
        """Get current bucket stats for user."""
        bucket = self.user_buckets.get(uuid)
        if not bucket:
            return {"rate": 0, "available": 0, "capacity": 0}
        bucket._refill()
        return {
            "rate_bps": bucket.rate,
            "rate_mbps": round(bucket.rate * 8 / 1_000_000, 2),
            "available_bytes": int(bucket.tokens),
            "available_mb": round(bucket.tokens / 1_000_000, 2),
            "capacity_bytes": int(bucket.capacity),
            "utilization": round((1 - bucket.tokens / bucket.capacity) * 100, 1) if bucket.capacity > 0 else 0,
        }


# Global rate limit manager
_rate_manager = RateLimitManager()


async def get_rate_manager() -> RateLimitManager:
    return _rate_manager


# ═══════════════════════════════════════════════════════════════════════════════
# Convenience Functions
# ═══════════════════════════════════════════════════════════════════════════════

async def throttle_user(uuid: str, nbytes: int, rate_bps: float):
    """Throttle user traffic (blocking wait)."""
    await _rate_manager.wait_user(uuid, nbytes, rate_bps)


async def throttle_connection(session_id: str, nbytes: int, rate_bps: float):
    """Throttle connection traffic (blocking wait)."""
    await _rate_manager.wait_connection(session_id, nbytes, rate_bps)


async def check_user_quota(uuid: str, nbytes: int, rate_bps: float) -> bool:
    """Check if user can send nbytes without waiting (non-blocking)."""
    return await _rate_manager.consume_user(uuid, nbytes, rate_bps)


async def check_connection_quota(session_id: str, nbytes: int, rate_bps: float) -> bool:
    """Check if connection can send nbytes without waiting."""
    return await _rate_manager.consume_connection(session_id, nbytes, rate_bps)


def reset_user_limit(uuid: str):
    """Reset user's rate limit bucket."""
    _rate_manager.user_buckets.pop(uuid, None)


def reset_connection_limit(session_id: str):
    """Reset connection's rate limit bucket."""
    _rate_manager.connection_limiters.pop(session_id, None)


def get_user_limit_stats(uuid: str) -> dict:
    return _rate_manager.get_user_stats(uuid)


# ═══════════════════════════════════════════════════════════════════════════════
# Speed Limit Parsing Helpers
# ═══════════════════════════════════════════════════════════════════════════════

def parse_speed_limit(value: float, unit: str) -> int:
    """
    Parse speed limit to bytes per second.
    Units: MBIT (Mbps), KB (KB/s), MB (MB/s)
    """
    if value <= 0:
        return 0

    unit = (unit or "MBIT").upper()

    if unit in ("MBIT", "MBPS"):
        return int(value * 1_000_000 / 8)  # Mbps to bytes/sec
    elif unit == "KB":
        return int(value * 1024)
    elif unit == "MB":
        return int(value * 1024 * 1024)
    elif unit == "GB":
        return int(value * 1024 * 1024 * 1024)
    elif unit in ("B", "BYTES"):
        return int(value)

    # Default to Mbps
    return int(value * 1_000_000 / 8)


def format_speed(bps: int) -> str:
    """Format bytes/sec to human readable string."""
    if bps <= 0:
        return "Unlimited"

    mbps = bps * 8 / 1_000_000
    if mbps >= 1:
        return f"{mbps:.1f} Mbps"
    kbps = bps * 8 / 1000
    if kbps >= 1:
        return f"{kbps:.1f} Kbps"
    return f"{bps * 8:.0f} bps"


# ═══════════════════════════════════════════════════════════════════════════════
# Traffic Accounting (Hourly Aggregates)
# ═══════════════════════════════════════════════════════════════════════════════

class TrafficAccountant:
    """Track hourly traffic aggregates in memory, flush to DB periodically."""

    def __init__(self):
        self.hourly: Dict[str, Dict[str, int]] = defaultdict(lambda: {
            "up": 0,
            "down": 0,
            "requests": 0,
        })
        self._lock = asyncio.Lock()

    def record(self, hour_key: str, up: int = 0, down: int = 0, requests: int = 0):
        with self._lock:
            self.hourly[hour_key]["up"] += up
            self.hourly[hour_key]["down"] += down
            self.hourly[hour_key]["requests"] += requests

    def get_hourly(self, hours: int = 24) -> Dict[str, Dict[str, int]]:
        """Get last N hours of traffic."""
        cutoff = time.time() - hours * 3600
        result = {}
        for hour_key, data in self.hourly.items():
            try:
                hour_ts = time.mktime(time.strptime(hour_key, "%Y-%m-%d %H:00"))
                if hour_ts >= cutoff:
                    result[hour_key] = data.copy()
            except ValueError:
                continue
        return dict(sorted(result.items()))

    def get_current_hour(self) -> Dict[str, int]:
        now = time.strftime("%Y-%m-%d %H:00")
        with self._lock:
            return self.hourly[now].copy()

    def clear_old(self, hours: int = 48):
        """Remove data older than N hours."""
        cutoff = time.time() - hours * 3600
        with self._lock:
            to_delete = []
            for hour_key in self.hourly:
                try:
                    hour_ts = time.mktime(time.strptime(hour_key, "%Y-%m-%d %H:00"))
                    if hour_ts < cutoff:
                        to_delete.append(hour_key)
                except ValueError:
                    to_delete.append(hour_key)
            for k in to_delete:
                del self.hourly[k]


# Global traffic accountant
_traffic_accountant = TrafficAccountant()


def record_traffic(up: int = 0, down: int = 0, requests: int = 0):
    """Record traffic for current hour."""
    hour_key = time.strftime("%Y-%m-%d %H:00")
    _traffic_accountant.record(hour_key, up, down, requests)


def get_hourly_traffic(hours: int = 24) -> Dict[str, Dict[str, int]]:
    return _traffic_accountant.get_hourly(hours)


def get_current_hour_traffic() -> Dict[str, int]:
    return _traffic_accountant.get_current_hour()


# ═══════════════════════════════════════════════════════════════════════════════
# Exports
# ═══════════════════════════════════════════════════════════════════════════════

__all__ = [
    "TokenBucket",
    "get_bucket",
    "reset_bucket",
    "throttle_user",
    "throttle_connection",
    "check_user_quota",
    "check_connection_quota",
    "reset_user_limit",
    "reset_connection_limit",
    "get_user_limit_stats",
    "AdaptiveQuotaGate",
    "AdaptiveFlow",
    "SessionRateLimiter",
    "RateLimitManager",
    "get_rate_manager",
    "parse_speed_limit",
    "format_speed",
    "TrafficAccountant",
    "record_traffic",
    "get_hourly_traffic",
    "get_current_hour_traffic",
    "_traffic_accountant",
    "_rate_manager",
]