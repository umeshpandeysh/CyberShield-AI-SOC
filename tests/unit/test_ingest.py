import pytest
import io
import uuid
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.main import app
from app.infra.db_session import get_db
from app.domain.models import Base, User, Email, URLIndicator
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

@pytest.fixture(name="token")
def fixture_token(client, db_session):
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
    return login_resp.json()["access_token"]

def test_ingest_email_success(client, token, db_session):
    # Setup mock EML content
    eml_content = (
        b"From: sender@attacker.com\n"
        b"To: victim@company.com\n"
        b"Subject: Urgent: Verify details\n"
        b"Date: Sat, 1 Aug 2026 21:13:55 +0530\n"
        b"Message-ID: <unique-message-id-12345@attacker.com>\n"
        b"Content-Type: text/plain\n\n"
        b"Please check http://attacker-link.com to unlock your account."
    )
    
    file_payload = {"file": ("test_mail.eml", io.BytesIO(eml_content), "message/rfc822")}
    headers = {"Authorization": f"Bearer {token}"}
    
    response = client.post("/api/v1/ingest/email", files=file_payload, headers=headers)
    assert response.status_code == 202
    
    data = response.json()
    assert "email_id" in data
    assert data["message_id"] == "<unique-message-id-12345@attacker.com>"
    assert data["status"] == "Queued"
    
    # Assert database insertion
    email_record = db_session.query(Email).filter(Email.message_id == data["message_id"]).first()
    assert email_record is not None
    assert email_record.sender == "sender@attacker.com"
    assert email_record.subject == "Urgent: Verify details"
    
    # Check URLs extracted
    url_records = db_session.query(URLIndicator).filter(URLIndicator.email_id == email_record.id).all()
    assert len(url_records) == 1
    assert url_records[0].url == "http://attacker-link.com"

def test_ingest_email_duplicate(client, token, db_session):
    eml_content = (
        b"From: sender@attacker.com\n"
        b"To: victim@company.com\n"
        b"Subject: Check details\n"
        b"Message-ID: <duplicate-id-999@attacker.com>\n\n"
        b"Test message body."
    )
    
    file_payload = {"file": ("test_mail.eml", io.BytesIO(eml_content), "message/rfc822")}
    headers = {"Authorization": f"Bearer {token}"}
    
    # First ingest
    response1 = client.post("/api/v1/ingest/email", files=file_payload, headers=headers)
    assert response1.status_code == 202
    
    # Second duplicate ingest
    file_payload_dup = {"file": ("test_mail.eml", io.BytesIO(eml_content), "message/rfc822")}
    response2 = client.post("/api/v1/ingest/email", files=file_payload_dup, headers=headers)
    assert response2.status_code == 400
    assert "already been ingested" in response2.json()["detail"]

def test_ingest_email_invalid_format(client, token):
    file_payload = {"file": ("test_mail.txt", io.BytesIO(b"Hello world"), "text/plain")}
    headers = {"Authorization": f"Bearer {token}"}
    
    response = client.post("/api/v1/ingest/email", files=file_payload, headers=headers)
    assert response.status_code == 400
    assert "Only RFC822 (.eml) files are supported" in response.json()["detail"]
