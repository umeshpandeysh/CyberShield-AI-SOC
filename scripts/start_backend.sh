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
    
    # Determine migration strategy based on database state
    MIGRATION_ACTION=$(python3 -c "
import sys, os
from sqlalchemy import inspect, create_engine
sys.path.insert(0, os.path.abspath('backend'))
sys.path.insert(0, os.path.abspath('.'))

try:
    from app.infra.config import settings
    db_url = settings.database_url
    if db_url.startswith('postgres://'):
        db_url = db_url.replace('postgres://', 'postgresql://', 1)

    engine = create_engine(db_url)
    inspector = inspect(engine)
    tables = inspector.get_table_names()

    if 'alembic_version' in tables:
        print('UPGRADE')
    elif any(t in tables for t in ['users', 'emails', 'alerts']):
        print('STAMP_AND_UPGRADE')
    else:
        print('UPGRADE')
except Exception as e:
    print('UPGRADE')
")

    if [ "$MIGRATION_ACTION" = "STAMP_AND_UPGRADE" ]; then
        echo "Existing database detected without Alembic history. Stamping head..."
        alembic -c backend/alembic.ini stamp head || { echo "ERROR: Alembic stamp failed!"; exit 1; }
        alembic -c backend/alembic.ini upgrade head || { echo "ERROR: Alembic upgrade failed!"; exit 1; }
    else
        echo "Database migration status check complete. Executing Alembic upgrade head..."
        alembic -c backend/alembic.ini upgrade head || { echo "ERROR: Alembic upgrade failed!"; exit 1; }
    fi
    echo "Alembic database migrations completed successfully."
fi

# Execute Uvicorn application server
exec uvicorn app.main:app --host 0.0.0.0 --port "${LISTEN_PORT}"
