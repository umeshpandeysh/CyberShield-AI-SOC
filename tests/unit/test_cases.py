import pytest
import uuid
from datetime import datetime
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.main import app
from app.infra.db_session import get_db
from app.domain.models import Base, User, Email, Alert, Case, CaseNote, CaseEvent, CaseEvidence, AuditLog
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
        email="case_analyst@company.com",
        password_hash=hashed_pwd,
        role="Analyst_L1",
        is_active=True
    )
    db_session.add(user)
    db_session.commit()

    login_resp = client.post(
        "/api/v1/auth/login",
        json={"email": "case_analyst@company.com", "password": "SecretPassword123"}
    )
    return login_resp.json()["access_token"], user

def test_create_case(client, token_and_user, db_session):
    token, user = token_and_user
    headers = {"Authorization": f"Bearer {token}"}
    payload = {
        "title": "Phishing Incident - Account Takeover Attempt",
        "description": "User reported suspicious login link",
        "severity": "High",
        "tags": "phishing,credential-harvesting"
    }

    response = client.post("/api/v1/cases", json=payload, headers=headers)
    assert response.status_code == 201
    data = response.json()
    assert "id" in data
    assert data["title"] == "Phishing Incident - Account Takeover Attempt"
    assert data["severity"] == "High"
    assert data["status"] == "Open"

    # Verify DB persistence
    case = db_session.query(Case).filter(Case.id == uuid.UUID(data["id"])).first()
    assert case is not None
    assert case.created_by == user.id

    # Verify audit log & case event creation
    event = db_session.query(CaseEvent).filter(CaseEvent.case_id == case.id).first()
    assert event is not None
    assert event.event_type == "CASE_CREATED"

    audit = db_session.query(AuditLog).filter(AuditLog.user_id == user.id, AuditLog.action == "CREATE_CASE").first()
    assert audit is not None

def test_list_cases_filtering_and_sorting(client, token_and_user, db_session):
    token, user = token_and_user
    headers = {"Authorization": f"Bearer {token}"}

    c1 = Case(
        id=uuid.uuid4(), title="High Severity Phish", severity="High", status="Open",
        created_by=user.id, created_at=datetime.utcnow(), tags="email,phish"
    )
    c2 = Case(
        id=uuid.uuid4(), title="Low Severity Spam", severity="Low", status="Closed",
        created_by=user.id, created_at=datetime.utcnow(), tags="spam"
    )
    db_session.add_all([c1, c2])
    db_session.commit()

    # Filter by severity
    resp = client.get("/api/v1/cases?severity=High", headers=headers)
    assert resp.status_code == 200
    data = resp.json()
    assert data["total"] == 1
    assert data["data"][0]["title"] == "High Severity Phish"

    # Filter by status
    resp = client.get("/api/v1/cases?status=Closed", headers=headers)
    assert resp.status_code == 200
    assert resp.json()["total"] == 1

    # Search filter
    resp = client.get("/api/v1/cases?search=Spam", headers=headers)
    assert resp.status_code == 200
    assert resp.json()["total"] == 1

def test_get_case_detail(client, token_and_user, db_session):
    token, user = token_and_user
    headers = {"Authorization": f"Bearer {token}"}

    case = Case(
        id=uuid.uuid4(), title="Investigate Malware Attachment", severity="Critical",
        status="Investigating", created_by=user.id, created_at=datetime.utcnow()
    )
    db_session.add(case)
    db_session.commit()

    resp = client.get(f"/api/v1/cases/{case.id}", headers=headers)
    assert resp.status_code == 200
    data = resp.json()
    assert data["id"] == str(case.id)
    assert data["title"] == "Investigate Malware Attachment"
    assert data["severity"] == "Critical"
    assert "notes" in data
    assert "timeline" in data
    assert "evidence" in data

def test_update_case_status_and_severity(client, token_and_user, db_session):
    token, user = token_and_user
    headers = {"Authorization": f"Bearer {token}"}

    case = Case(
        id=uuid.uuid4(), title="Suspicious Activity", severity="Medium",
        status="Open", created_by=user.id, created_at=datetime.utcnow()
    )
    db_session.add(case)
    db_session.commit()

    patch_payload = {
        "status": "Closed",
        "severity": "High"
    }

    resp = client.patch(f"/api/v1/cases/{case.id}", json=patch_payload, headers=headers)
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "Closed"
    assert data["severity"] == "High"

    db_session.refresh(case)
    assert case.status == "Closed"
    assert case.closed_at is not None

def test_add_and_list_notes(client, token_and_user, db_session):
    token, user = token_and_user
    headers = {"Authorization": f"Bearer {token}"}

    case = Case(
        id=uuid.uuid4(), title="Note Test Case", severity="Low",
        status="Open", created_by=user.id, created_at=datetime.utcnow()
    )
    db_session.add(case)
    db_session.commit()

    note_payload = {"content": "Initial triage complete. Malicious URL confirmed."}
    resp = client.post(f"/api/v1/cases/{case.id}/notes", json=note_payload, headers=headers)
    assert resp.status_code == 201
    n_data = resp.json()
    assert n_data["content"] == "Initial triage complete. Malicious URL confirmed."

    list_resp = client.get(f"/api/v1/cases/{case.id}/notes", headers=headers)
    assert list_resp.status_code == 200
    notes = list_resp.json()
    assert len(notes) == 1
    assert notes[0]["content"] == "Initial triage complete. Malicious URL confirmed."

def test_add_and_list_evidence(client, token_and_user, db_session):
    token, user = token_and_user
    headers = {"Authorization": f"Bearer {token}"}

    case = Case(
        id=uuid.uuid4(), title="Evidence Test Case", severity="High",
        status="Open", created_by=user.id, created_at=datetime.utcnow()
    )
    db_session.add(case)
    db_session.commit()

    ev_payload = {
        "evidence_type": "url",
        "reference_id": "http://evil-phish-domain.com/login",
        "description": "Phishing landing page extracted from email body"
    }
    resp = client.post(f"/api/v1/cases/{case.id}/evidence", json=ev_payload, headers=headers)
    assert resp.status_code == 201
    ev_data = resp.json()
    assert ev_data["evidence_type"] == "url"
    assert ev_data["reference_id"] == "http://evil-phish-domain.com/login"

    list_resp = client.get(f"/api/v1/cases/{case.id}/evidence", headers=headers)
    assert list_resp.status_code == 200
    ev_list = list_resp.json()
    assert len(ev_list) == 1

def test_get_timeline(client, token_and_user, db_session):
    token, user = token_and_user
    headers = {"Authorization": f"Bearer {token}"}

    case = Case(
        id=uuid.uuid4(), title="Timeline Test Case", severity="Medium",
        status="Open", created_by=user.id, created_at=datetime.utcnow()
    )
    db_session.add(case)
    db_session.commit()

    # Add a note to generate a timeline event
    client.post(f"/api/v1/cases/{case.id}/notes", json={"content": "Adding note to generate timeline event"}, headers=headers)

    t_resp = client.get(f"/api/v1/cases/{case.id}/timeline", headers=headers)
    assert t_resp.status_code == 200
    events = t_resp.json()
    assert len(events) >= 1
    assert any(e["event_type"] == "NOTE_ADDED" for e in events)
