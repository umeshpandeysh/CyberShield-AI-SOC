import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.main import app
from app.infra.db_session import get_db
from app.domain.models import Base, User
from app.adapters.security import get_password_hash

# SQLite in-memory setup for testing routing and endpoints
SQLALCHEMY_DATABASE_URL = "sqlite://"
engine = create_engine(
    SQLALCHEMY_DATABASE_URL,
    connect_args={"check_same_thread": False},
    poolclass=StaticPool,
)
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# Create tables in SQLite in-memory
Base.metadata.create_all(bind=engine)

@pytest.fixture(name="db_session")
def fixture_db_session():
    connection = engine.connect()
    transaction = connection.begin()
    session = TestingSessionLocal(bind=connection)
    
    yield session
    
    session.close()
    transaction.rollback()
    connection.close()

@pytest.fixture(name="client")
def fixture_client(db_session):
    def override_get_db():
        try:
            yield db_session
        finally:
            pass
            
    app.dependency_overrides[get_db] = override_get_db
    yield TestClient(app)
    app.dependency_overrides.clear()

def test_health_check(client):
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json()["status"] == "healthy"
    assert response.json()["service"] == "backend"

def test_login_success(client, db_session):
    # Seed a test user
    hashed_pwd = get_password_hash("SecretPassword123")
    user = User(
        email="test_analyst@company.com",
        password_hash=hashed_pwd,
        role="Analyst_L1",
        is_active=True
    )
    db_session.add(user)
    db_session.commit()
    
    # POST login
    response = client.post(
        "/api/v1/auth/login",
        json={"email": "test_analyst@company.com", "password": "SecretPassword123"}
    )
    
    assert response.status_code == 200
    data = response.json()
    assert "access_token" in data
    assert data["token_type"] == "bearer"
    assert data["role"] == "Analyst_L1"

def test_login_invalid_credentials(client, db_session):
    # Seed user
    hashed_pwd = get_password_hash("SecretPassword123")
    user = User(
        email="test_analyst@company.com",
        password_hash=hashed_pwd,
        role="Analyst_L1",
        is_active=True
    )
    db_session.add(user)
    db_session.commit()
    
    # Incorrect password
    response = client.post(
        "/api/v1/auth/login",
        json={"email": "test_analyst@company.com", "password": "wrong_password"}
    )
    assert response.status_code == 401
    assert response.json()["detail"] == "Invalid email or password"

def test_auth_me_success(client, db_session):
    # Seed user
    hashed_pwd = get_password_hash("SecretPassword123")
    user = User(
        email="test_analyst@company.com",
        password_hash=hashed_pwd,
        role="Analyst_L2",
        is_active=True
    )
    db_session.add(user)
    db_session.commit()
    
    # Login to get token
    login_resp = client.post(
        "/api/v1/auth/login",
        json={"email": "test_analyst@company.com", "password": "SecretPassword123"}
    )
    token = login_resp.json()["access_token"]
    
    # Fetch /me
    headers = {"Authorization": f"Bearer {token}"}
    response = client.get("/api/v1/auth/me", headers=headers)
    
    assert response.status_code == 200
    data = response.json()
    assert data["email"] == "test_analyst@company.com"
    assert data["role"] == "Analyst_L2"
    assert data["is_active"] is True

def test_auth_me_unauthorized(client):
    response = client.get("/api/v1/auth/me")
    assert response.status_code == 401
