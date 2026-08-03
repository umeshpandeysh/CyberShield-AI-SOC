from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
try:
    from app.infra.config import settings
except ImportError:
    from backend.app.infra.config import settings

# Create database engine with connection pooling parameters
engine = create_engine(
    settings.database_url,
    pool_pre_ping=True,      # Verify connection health before returning from pool
    pool_size=10,            # Keep up to 10 connections open
    max_overflow=20          # Allow up to 20 temporary extra connections under load
)

# SessionLocal is the session factory
SessionLocal = sessionmaker(
    autocommit=False,
    autoflush=False,
    bind=engine
)

# FastAPI DB Session Dependency
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
