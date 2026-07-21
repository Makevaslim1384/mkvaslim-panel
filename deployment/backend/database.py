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