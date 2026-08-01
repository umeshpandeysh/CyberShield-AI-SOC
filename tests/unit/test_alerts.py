import pytest
import uuid
from datetime import datetime
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.main import app
from app.infra.db_session import get_db
from app.domain.models import Base, User, Email, Alert, AuditLog
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

@pytest.fixture(name="token_and_user")
def fixture_token_and_user(client, db_session):
    hashed_pwd = get_password_hash("SecretPassword123")
    user = User(
        email="test_analyst@company.com",
        password_hash=hashed_pwd,
        role="Analyst_L1",
        is_active=True
    )
    db_session.add(user)
    db_session.commit()
    
    login_resp = client.post(
        "/api/v1/auth/login",
        json={"email": "test_analyst@company.com", "password": "SecretPassword123"}
    )
    return login_resp.json()["access_token"], user

def test_list_alerts(client, token_and_user, db_session):
    token, user = token_and_user
    
    # Seed an Email and Alert
    email = Email(
        id=uuid.uuid4(),
        message_id="<test-msg-11@attacker.com>",
        sender="attacker11@phish.com",
        recipient="victim@company.com",
        subject="Bank Notification Alert",
        raw_header="Header info",
        received_at=datetime.utcnow(),
        status="Completed"
    )
    alert = Alert(
        id=uuid.uuid4(),
        email_id=email.id,
        risk_score=0.88,
        status="OPEN"
    )
    db_session.add(email)
    db_session.add(alert)
    db_session.commit()
    
    headers = {"Authorization": f"Bearer {token}"}
    response = client.get("/api/v1/alerts?status=OPEN", headers=headers)
    assert response.status_code == 200
    
    data = response.json()
    assert data["total"] == 1
    assert data["data"][0]["id"] == str(alert.id)
    assert data["data"][0]["sender"] == "attacker11@phish.com"
    assert data["data"][0]["risk_score"] == 0.88

def test_get_alert_detail(client, token_and_user, db_session):
    token, user = token_and_user
    
    # Seed Email & Alert
    email = Email(
        id=uuid.uuid4(),
        message_id="<test-msg-22@attacker.com>",
        sender="attacker22@phish.com",
        recipient="victim@company.com",
        subject="Secure Notification",
        raw_header="Header info",
        received_at=datetime.utcnow(),
        status="Completed"
    )
    alert = Alert(
        id=uuid.uuid4(),
        email_id=email.id,
        risk_score=0.91,
        status="OPEN"
    )
    db_session.add(email)
    db_session.add(alert)
    db_session.commit()
    
    headers = {"Authorization": f"Bearer {token}"}
    response = client.get(f"/api/v1/alerts/{str(alert.id)}", headers=headers)
    assert response.status_code == 200
    
    data = response.json()
    assert data["id"] == str(alert.id)
    assert data["email"]["sender"] == "attacker22@phish.com"
    assert data["email"]["subject"] == "Secure Notification"

def test_triage_alert(client, token_and_user, db_session):
    token, user = token_and_user
    
    # Seed Email & Alert
    email = Email(
        id=uuid.uuid4(),
        message_id="<test-msg-33@attacker.com>",
        sender="attacker33@phish.com",
        recipient="victim@company.com",
        subject="Important Action Required",
        raw_header="Header info",
        received_at=datetime.utcnow(),
        status="Completed"
    )
    alert = Alert(
        id=uuid.uuid4(),
        email_id=email.id,
        risk_score=0.95,
        status="OPEN"
    )
    db_session.add(email)
    db_session.add(alert)
    db_session.commit()
    
    # Patch status to RESOLVED_QUARANTINED
    headers = {"Authorization": f"Bearer {token}"}
    triage_payload = {
        "status": "RESOLVED_QUARANTINED",
        "comments": "Confirmed phishing threat."
    }
    
    response = client.patch(
        f"/api/v1/alerts/{str(alert.id)}/triage",
        json=triage_payload,
        headers=headers
    )
    
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "RESOLVED_QUARANTINED"
    assert data["triage_by"] == str(user.id)
    
    # Verify mutations inside DB
    db_session.refresh(alert)
    assert alert.status == "RESOLVED_QUARANTINED"
    
    # Verify audit log created
    audit_entry = db_session.query(AuditLog).filter(AuditLog.user_id == user.id).first()
    assert audit_entry is not None
    assert audit_entry.action == "TRIAGE_ALERT"
    assert "Confirmed phishing threat." in audit_entry.details
