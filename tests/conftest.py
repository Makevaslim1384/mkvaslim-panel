"""
MaKeVaslim Panel - Pytest Configuration
"""
import sys
from pathlib import Path

# Add backend to path
sys.path.insert(0, str(Path(__file__).parent.parent / "backend"))

import pytest
import asyncio
from typing import AsyncGenerator

from backend.database import DatabaseManager, User
from backend.config import settings


@pytest.fixture(scope="session")
def event_loop() -> asyncio.AbstractEventLoop:
    """Create event loop for session."""
    loop = asyncio.new_event_loop()
    yield loop
    loop.close()


@pytest.fixture(scope="function")
async def db() -> AsyncGenerator[DatabaseManager, None]:
    """Create test database."""
    import tempfile
    import os
    
    # Create temp database file
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tmp:
        db_path = tmp.name
    
    try:
        db = DatabaseManager(db_path)
        await db.initialize()
        yield db
    finally:
        await db.close()
        os.unlink(db_path)


@pytest.fixture
def sample_user() -> User:
    """Create a sample user for testing."""
    return User(
        username="testuser",
        uuid="12345678-1234-1234-1234-123456789abc",
        limit_bytes=1024 * 1024 * 1024,  # 1 GB
        used_bytes=0,
        speed_limit_bps=1024 * 1024 * 10,  # 10 Mbps
        ip_limit=2,
        expiry_days=30,
        protocol="vless",
        transport="ws",
        fingerprint="chrome",
        alpn="h2,http/1.1",
        port="443",
        ips="",
        active=True,
    )


# Pytest configuration
def pytest_configure(config):
    config.addinivalue_line(
        "markers", "asyncio: mark test as async"
    )
    config.addinivalue_line(
        "markers", "integration: mark test as integration test"
    )
    config.addinivalue_line(
        "markers", "unit: mark test as unit test"
    )
    config.addinivalue_line(
        "markers", "slow: mark test as slow"
    )