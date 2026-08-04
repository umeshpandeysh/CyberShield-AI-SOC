#!/usr/bin/env bash
set -e

echo "=== Starting CyberShield-AI-SOC Backend Server ==="

# Convert postgres:// to postgresql:// if needed for Render compatibility
if [ -n "$DATABASE_URL" ]; then
    export DATABASE_URL=$(echo "$DATABASE_URL" | sed 's/^postgres:\/\//postgresql:\/\//')
    echo "DATABASE_URL scheme verified for SQLAlchemy 2.0."
fi

# Set PYTHONPATH to include backend directory
export PYTHONPATH="${PYTHONPATH}:$(pwd)/backend:$(pwd)"

# Port handling for Render environment
LISTEN_PORT="${PORT:-8000}"
echo "Binding FastAPI web server to 0.0.0.0:${LISTEN_PORT}"

# Run database migrations if alembic is configured
if [ -f "backend/alembic.ini" ]; then
    echo "Executing Alembic database migrations..."
    (cd backend && python -m alembic upgrade head) || echo "Alembic migration notice: Continuing with automatic schema initialization."
fi

# Execute Uvicorn application server
exec uvicorn app.main:app --host 0.0.0.0 --port "${LISTEN_PORT}"
