#!/bin/bash
set -e

echo "🚀 Starting MaKeVaslim Panel..."

# Export environment variables with defaults
export ADMIN_PASSWORD=${ADMIN_PASSWORD:-"MakeVaslim2024!"}
export SECRET_KEY=${SECRET_KEY:-""}
export DATA_DIR=${DATA_DIR:-"/data"}
# CRITICAL: Inside container, ALWAYS use port 8000. Railway maps external $PORT to container's 8000.
export HOST=${HOST:-"0.0.0.0"}

# Create data directory if not exists
mkdir -p "$DATA_DIR"

# Initialize database in BACKGROUND (non-blocking)
echo "🔧 Starting database initialization in background..."
cd /app && PYTHONPATH=/app python3 -c "
from backend.database import DatabaseManager
from backend.config import settings
import asyncio

async def init():
    try:
        db = DatabaseManager(settings.DB_PATH)
        await db.initialize()
        print('✅ Database initialized')
    except Exception as e:
        print(f'⚠️ Database init warning: {e}')

asyncio.run(init())
" 

# Run migrations in BACKGROUND (non-blocking)
echo "🔄 Starting migrations in background..."
PYTHONPATH=/app python3 -c "
from backend.database import DatabaseManager
from backend.config import settings
import asyncio

async def migrate():
    try:
        db = DatabaseManager(settings.DB_PATH)
        await db.initialize()
        print('✅ Migrations completed')
    except Exception as e:
        print(f'⚠️ Migration warning: {e}')

asyncio.run(migrate())
" 

# Start the application IMMEDIATELY - ALWAYS on port 8000 inside container
echo "🚀 Starting MaKeVaslim Panel on \${HOST}:8000..."
# جایگزین خط آخر
exec python3 -m uvicorn backend.main:app --host "${HOST}" --port "${PORT:-8000}" --workers 1
