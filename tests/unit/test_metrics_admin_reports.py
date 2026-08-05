import pytest
import uuid
from datetime import datetime
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.main import app
from app.infra.db_session import get_db
from app.domain.models import Base, User, Email, Alert, Case, AuditLog
from app.adapters.security import get_password_hash

# SQLite in-memory setup for testing
SQLALCHEMY_DATABASE_URL = "sqlite://"
engine = create_engine(
    SQLALCHEMY_DATABASE_URL,
    connect_args={"check_same_thread": False},
    poolclass=StaticPool,
)
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
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


@pytest.fixture(name="admin_token")
def fixture_admin_token(client, db_session):
    hashed_pwd = get_password_hash("AdminPass123!")
    user = User(
        email="admin_user@cybershield.io",
        password_hash=hashed_pwd,
        role="Admin",
        is_active=True
    )
    db_session.add(user)
    db_session.commit()

    login_resp = client.post(
        "/api/v1/auth/login",
        json={"email": "admin_user@cybershield.io", "password": "AdminPass123!"}
    )
    return login_resp.json()["access_token"], user


# ===== 1. Metrics & Analytics Tests =====

def test_get_metrics_summary(client, admin_token, db_session):
    token, _ = admin_token
    headers = {"Authorization": f"Bearer {token}"}

    resp = client.get("/api/v1/metrics/summary", headers=headers)
    assert resp.status_code == 200
    data = resp.json()
    assert "statistics" in data
    assert "threat_distribution" in data
    assert "total_processed_today" in data["statistics"]


def test_get_analytics(client, admin_token, db_session):
    token, _ = admin_token
    headers = {"Authorization": f"Bearer {token}"}

    resp = client.get("/api/v1/metrics/analytics", headers=headers)
    assert resp.status_code == 200
    data = resp.json()
    assert "threat_trends_7d" in data
    assert len(data["threat_trends_7d"]) == 7


# ===== 2. Reports Tests =====

def test_generate_case_report(client, admin_token, db_session):
    token, user = admin_token
    headers = {"Authorization": f"Bearer {token}"}

    case = Case(
        id=uuid.uuid4(),
        title="Report Test Incident",
        description="Testing report generation",
        severity="High",
        status="Open",
        created_by=user.id,
        created_at=datetime.utcnow()
    )
    db_session.add(case)
    db_session.commit()

    resp = client.get(f"/api/v1/reports/case/{case.id}", headers=headers)
    assert resp.status_code == 200
    data = resp.json()
    assert data["case_details"]["title"] == "Report Test Incident"

    # Text report
    txt_resp = client.get(f"/api/v1/reports/case/{case.id}?format=text", headers=headers)
    assert txt_resp.status_code == 200
    assert "CYBERSHIELD-AI-SOC EXECUTIVE INCIDENT REPORT" in txt_resp.text


def test_get_executive_summary_report(client, admin_token):
    token, _ = admin_token
    headers = {"Authorization": f"Bearer {token}"}

    resp = client.get("/api/v1/reports/summary", headers=headers)
    assert resp.status_code == 200
    assert "executive_summary" in resp.json()


# ===== 3. Admin & User Management Tests =====

def test_admin_list_users(client, admin_token):
    token, _ = admin_token
    headers = {"Authorization": f"Bearer {token}"}

    resp = client.get("/api/v1/admin/users", headers=headers)
    assert resp.status_code == 200
    assert len(resp.json()) >= 1


def test_admin_create_user(client, admin_token, db_session):
    token, _ = admin_token
    headers = {"Authorization": f"Bearer {token}"}

    payload = {
        "email": "new_analyst@cybershield.io",
        "password": "SecurePassword123!",
        "role": "Analyst_L2"
    }

    resp = client.post("/api/v1/admin/users", json=payload, headers=headers)
    assert resp.status_code == 201
    data = resp.json()
    assert data["email"] == "new_analyst@cybershield.io"
    assert data["role"] == "Analyst_L2"


def test_admin_audit_logs(client, admin_token):
    token, _ = admin_token
    headers = {"Authorization": f"Bearer {token}"}

    resp = client.get("/api/v1/admin/audit-logs", headers=headers)
    assert resp.status_code == 200
    assert isinstance(resp.json(), list)


# ===== 4. Settings Tests =====

def test_get_and_update_settings(client, admin_token):
    token, _ = admin_token
    headers = {"Authorization": f"Bearer {token}"}

    get_resp = client.get("/api/v1/settings", headers=headers)
    assert get_resp.status_code == 200
    assert "confidence_threshold" in get_resp.json()

    patch_resp = client.patch(
        "/api/v1/settings",
        json={"confidence_threshold": 0.85},
        headers=headers
    )
    assert patch_resp.status_code == 200
    assert patch_resp.json()["confidence_threshold"] == 0.85
