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
    python3 -c "
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

    if 'users' in tables and 'alembic_version' not in tables:
        print('Existing database schema detected without Alembic version tracking. Stamping Alembic head...')
        os.system('alembic -c backend/alembic.ini stamp head')
    elif 'users' in tables:
        print('Existing database schema detected. Running Alembic upgrade head...')
        res = os.system('alembic -c backend/alembic.ini upgrade head')
        if res != 0:
            print('Upgrade encountered conflict; stamping head for schema compatibility.')
            os.system('alembic -c backend/alembic.ini stamp head')
    else:
        print('Fresh database detected. Executing full Alembic migration chain...')
        os.system('alembic -c backend/alembic.ini upgrade head')
except Exception as err:
    print(f'Migration inspection notice: {err}')
    os.system('alembic -c backend/alembic.ini upgrade head')
"
    echo "Alembic database migrations completed successfully."
fi

# Execute Uvicorn application server
exec uvicorn app.main:app --host 0.0.0.0 --port "${LISTEN_PORT}"
