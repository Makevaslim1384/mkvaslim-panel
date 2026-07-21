#!/bin/bash
set -e

echo "🚀 Starting MaKeVaslim Panel..."

# Export environment variables with defaults
export ADMIN_PASSWORD=${ADMIN_PASSWORD:-"MakeVaslim2024!"}
export SECRET_KEY=${SECRET_KEY:-""}
export DATA_DIR=${DATA_DIR:-"/data"}
export PORT=${PORT:-8000}
export HOST=${HOST:-"0.0.0.0"}

# Create data directory if not exists
mkdir -p "$DATA_DIR"

# Initialize database if needed
echo "🔧 Initializing database..."
python -c "
from backend.database import DatabaseManager
from backend.config import settings
import asyncio

async def init():
    db = DatabaseManager(settings.DB_PATH)
    await db.initialize()
    print('✅ Database initialized')

asyncio.run(init())
"

# Run migrations if needed
echo "🔄 Running migrations..."
python -c "
from backend.database import DatabaseManager
from backend.config import settings
import asyncio

async def migrate():
    db = DatabaseManager(settings.DB_PATH)
    await db.initialize()
    # Add any migration logic here
    print('✅ Migrations completed')

asyncio.run(migrate())
"

# Start the application
echo "🚀 Starting MaKeVaslim Panel on ${HOST}:${PORT}..."
exec python -m uvicorn backend.main:app --host "${HOST}" --port "${PORT}" --workers 1