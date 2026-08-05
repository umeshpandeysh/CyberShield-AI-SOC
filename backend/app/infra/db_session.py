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

def init_db():
    """Seeds default system users if the database tables exist."""
    try:
        from app.domain.models import User
        from app.adapters.security import get_password_hash
    except ImportError:
        from backend.app.domain.models import User
        from backend.app.adapters.security import get_password_hash

    db = SessionLocal()
    try:
        analyst = db.query(User).filter(User.email == "analyst@cybershield.io").first()
        if not analyst:
            analyst = User(
                email="analyst@cybershield.io",
                password_hash=get_password_hash("Password123!"),
                role="Analyst_L2",
                is_active=True
            )
            db.add(analyst)

        admin = db.query(User).filter(User.email == "admin@cybershield.io").first()
        if not admin:
            admin = User(
                email="admin@cybershield.io",
                password_hash=get_password_hash("Password123!"),
                role="Admin",
                is_active=True
            )
            db.add(admin)

        db.commit()
    except Exception as e:
        db.rollback()
        print(f"init_db notice: {e}")
    finally:
        db.close()
