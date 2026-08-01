import pytest
import io
import uuid
from unittest.mock import patch, MagicMock
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.main import app
from app.infra.db_session import get_db
from app.domain.models import Base, User, Email, Attachment, YaraMatch, Alert
from app.adapters.security import get_password_hash

# SQLite setup for testing
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

# --- 1. Test Clean Attachment ---
@patch("app.adapters.threat_scanner.scan_bytes_clamav")
def test_threat_scanning_clean_attachments(mock_clamav, client, token, db_session):
    # Mock ClamAV to return clean
    mock_clamav.return_value = (False, "")
    
    eml_content = (
        b"From: partner@company.com\n"
        b"To: me@company.com\n"
        b"Subject: Clean email with attachment\n"
        b"Message-ID: <clean-id-123@company.com>\n"
        b"MIME-Version: 1.0\n"
        b"Content-Type: multipart/mixed; boundary=\"boundary\"\n\n"
        b"--boundary\n"
        b"Content-Type: text/plain\n\n"
        b"Attached is the weekly report.\n\n"
        b"--boundary\n"
        b"Content-Type: text/plain\n"
        b"Content-Disposition: attachment; filename=\"report.txt\"\n\n"
        b"Weekly report text contents."
        b"\n--boundary--"
    )
    
    file_payload = {"file": ("clean.eml", io.BytesIO(eml_content), "message/rfc822")}
    headers = {"Authorization": f"Bearer {token}"}
    
    response = client.post("/api/v1/ingest/email", files=file_payload, headers=headers)
    assert response.status_code == 200
    
    data = response.json()
    assert data["risk_score"] < 0.5  # Low risk with clean attachments
    
    # Assert database values
    email_rec = db_session.query(Email).filter(Email.message_id == "<clean-id-123@company.com>").first()
    assert email_rec is not None
    assert len(email_rec.attachments) == 1
    assert email_rec.attachments[0].scanning_status == "Scanned"
    assert email_rec.attachments[0].virus_found is False

# --- 2. Test Infected Attachment ---
@patch("app.adapters.threat_scanner.scan_bytes_clamav")
def test_threat_scanning_infected_attachments(mock_clamav, client, token, db_session):
    # Mock ClamAV to return virus found
    mock_clamav.return_value = (True, "Win.Trojan.Generic-12345")
    
    eml_content = (
        b"From: attacker@malicious.com\n"
        b"To: victim@company.com\n"
        b"Subject: Immediate action required\n"
        b"Message-ID: <infected-id-123@attacker.com>\n"
        b"MIME-Version: 1.0\n"
        b"Content-Type: multipart/mixed; boundary=\"boundary\"\n\n"
        b"--boundary\n"
        b"Content-Type: text/plain\n\n"
        b"Check invoice.\n\n"
        b"--boundary\n"
        b"Content-Type: application/octet-stream\n"
        b"Content-Disposition: attachment; filename=\"invoice.exe\"\n\n"
        b"Infected payload structure."
        b"\n--boundary--"
    )
    
    file_payload = {"file": ("malicious.eml", io.BytesIO(eml_content), "message/rfc822")}
    headers = {"Authorization": f"Bearer {token}"}
    
    response = client.post("/api/v1/ingest/email", files=file_payload, headers=headers)
    assert response.status_code == 200
    
    data = response.json()
    assert data["risk_score"] == 0.99  # Malware risk
    
    # Assert Alert record created
    email_rec = db_session.query(Email).filter(Email.message_id == "<infected-id-123@attacker.com>").first()
    assert email_rec is not None
    assert email_rec.attachments[0].virus_found is True
    assert email_rec.attachments[0].threat_label == "Win.Trojan.Generic-12345"
    
    alert_rec = db_session.query(Alert).filter(Alert.email_id == email_rec.id).first()
    assert alert_rec is not None
    assert alert_rec.risk_score == 0.99
    assert alert_rec.status == "OPEN"

# --- 3. Test YARA Rules Matches ---
@patch("app.adapters.threat_scanner.scan_bytes_clamav")
def test_threat_scanning_yara_matches(mock_clamav, client, token, db_session):
    mock_clamav.return_value = (False, "")
    
    eml_content = (
        b"From: phisher@attacker.com\n"
        b"To: victim@company.com\n"
        b"Subject: Urgent security action\n"  # Triggers default YARA rule Phishing_Suspicious_Keywords
        b"Message-ID: <yara-match-id@attacker.com>\n"
        b"Content-Type: text/plain\n\n"
        b"Please verify your account password immediately."
    )
    
    file_payload = {"file": ("phish.eml", io.BytesIO(eml_content), "message/rfc822")}
    headers = {"Authorization": f"Bearer {token}"}
    
    response = client.post("/api/v1/ingest/email", files=file_payload, headers=headers)
    assert response.status_code == 200
    
    data = response.json()
    assert data["risk_score"] >= 0.75  # YARA risk rating (may be higher with AI fusion)
    
    # Assert database YARA match values
    email_rec = db_session.query(Email).filter(Email.message_id == "<yara-match-id@attacker.com>").first()
    assert email_rec is not None
    assert len(email_rec.yara_matches) > 0
    assert email_rec.yara_matches[0].rule_name == "Phishing_Suspicious_Keywords"
    
    alert_rec = db_session.query(Alert).filter(Alert.email_id == email_rec.id).first()
    assert alert_rec is not None
    assert alert_rec.risk_score >= 0.75

# --- 4. Test Scanner Unavailable (Degrades Gracefully) ---
@patch("app.adapters.threat_scanner.scan_bytes_clamav")
def test_threat_scanning_scanner_unavailable(mock_clamav, client, token, db_session):
    # Simulate connection failure in ClamAV socket communication
    mock_clamav.side_effect = Exception("ClamAV socket timed out or is down")
    
    eml_content = (
        b"From: client@company.com\n"
        b"To: helpdesk@company.com\n"
        b"Subject: Ticket inquiry\n"
        b"Message-ID: <degraded-id-444@company.com>\n"
        b"MIME-Version: 1.0\n"
        b"Content-Type: multipart/mixed; boundary=\"boundary\"\n\n"
        b"--boundary\n"
        b"Content-Type: text/plain\n\n"
        b"Ticket logs inside.\n\n"
        b"--boundary\n"
        b"Content-Type: text/plain\n"
        b"Content-Disposition: attachment; filename=\"ticket.log\"\n\n"
        b"Log entries..."
        b"\n--boundary--"
    )
    
    file_payload = {"file": ("degraded.eml", io.BytesIO(eml_content), "message/rfc822")}
    headers = {"Authorization": f"Bearer {token}"}
    
    # Should complete upload gracefully returning status 200 rather than throwing an unhandled exception
    response = client.post("/api/v1/ingest/email", files=file_payload, headers=headers)
    assert response.status_code == 200
    
    # Assert scanning status is stored as Failed due to exception
    email_rec = db_session.query(Email).filter(Email.message_id == "<degraded-id-444@company.com>").first()
    assert email_rec is not None
    assert email_rec.attachments[0].scanning_status == "Failed"
    assert "Scan error" in email_rec.attachments[0].threat_label

# --- 5. Test Corrupted/Empty Attachment payload ---
@patch("app.adapters.threat_scanner.scan_bytes_clamav")
def test_threat_scanning_corrupted_attachments(mock_clamav, client, token, db_session):
    mock_clamav.return_value = (False, "")
    
    eml_content = (
        b"From: tester@company.com\n"
        b"To: admin@company.com\n"
        b"Subject: Empty file attachment\n"
        b"Message-ID: <empty-id-555@company.com>\n"
        b"MIME-Version: 1.0\n"
        b"Content-Type: multipart/mixed; boundary=\"boundary\"\n\n"
        b"--boundary\n"
        b"Content-Type: text/plain\n\n"
        b"Empty attachment below.\n\n"
        b"--boundary\n"
        b"Content-Type: application/octet-stream\n"
        b"Content-Disposition: attachment; filename=\"corrupt.dat\"\n\n"
        b""  # Zero-byte payload
        b"\n--boundary--"
    )
    
    file_payload = {"file": ("empty.eml", io.BytesIO(eml_content), "message/rfc822")}
    headers = {"Authorization": f"Bearer {token}"}
    
    response = client.post("/api/v1/ingest/email", files=file_payload, headers=headers)
    assert response.status_code == 200
    
    email_rec = db_session.query(Email).filter(Email.message_id == "<empty-id-555@company.com>").first()
    assert email_rec is not None
    assert len(email_rec.attachments) == 1
    assert email_rec.attachments[0].file_size == 0

# --- 6. Test Large Attachment Payload ---
@patch("app.adapters.threat_scanner.scan_bytes_clamav")
def test_threat_scanning_large_attachments(mock_clamav, client, token, db_session):
    mock_clamav.return_value = (False, "")
    
    # 1MB payload of zeros to represent larger files
    large_payload = b"\0" * (1024 * 1024)
    
    eml_content = (
        b"From: backup@company.com\n"
        b"To: sysadmin@company.com\n"
        b"Subject: Nightly backup zip\n"
        b"Message-ID: <large-id-888@company.com>\n"
        b"MIME-Version: 1.0\n"
        b"Content-Type: multipart/mixed; boundary=\"boundary\"\n\n"
        b"--boundary\n"
        b"Content-Type: text/plain\n\n"
        b"Backup data.\n\n"
        b"--boundary\n"
        b"Content-Type: application/zip\n"
        b"Content-Disposition: attachment; filename=\"backup.zip\"\n\n" +
        large_payload +
        b"\n--boundary--"
    )
    
    file_payload = {"file": ("large.eml", io.BytesIO(eml_content), "message/rfc822")}
    headers = {"Authorization": f"Bearer {token}"}
    
    response = client.post("/api/v1/ingest/email", files=file_payload, headers=headers)
    assert response.status_code == 200
    
    email_rec = db_session.query(Email).filter(Email.message_id == "<large-id-888@company.com>").first()
    assert email_rec is not None
    assert len(email_rec.attachments) == 1
    assert email_rec.attachments[0].file_size >= (1024 * 1024)

# --- 7. Test Multiple Mixed Attachments ---
@patch("app.adapters.threat_scanner.scan_bytes_clamav")
def test_threat_scanning_multiple_attachments(mock_clamav, client, token, db_session):
    # Mock scanning sequence: 1st file clean, 2nd file infected
    mock_clamav.side_effect = [
        (False, ""),
        (True, "Win.Virus.Test-321")
    ]
    
    eml_content = (
        b"From: dual@company.com\n"
        b"To: security@company.com\n"
        b"Subject: Dual files alert\n"
        b"Message-ID: <dual-files-id@company.com>\n"
        b"MIME-Version: 1.0\n"
        b"Content-Type: multipart/mixed; boundary=\"boundary\"\n\n"
        b"--boundary\n"
        b"Content-Type: text/plain\n\n"
        b"Two attachments.\n\n"
        b"--boundary\n"
        b"Content-Type: text/plain\n"
        b"Content-Disposition: attachment; filename=\"clean_doc.txt\"\n\n"
        b"Clean text data"
        b"\n--boundary\n"
        b"Content-Type: application/octet-stream\n"
        b"Content-Disposition: attachment; filename=\"bad_script.exe\"\n\n"
        b"Malicious virus payload"
        b"\n--boundary--"
    )
    
    file_payload = {"file": ("dual.eml", io.BytesIO(eml_content), "message/rfc822")}
    headers = {"Authorization": f"Bearer {token}"}
    
    response = client.post("/api/v1/ingest/email", files=file_payload, headers=headers)
    assert response.status_code == 200
    
    data = response.json()
    assert data["risk_score"] == 0.99  # Infected file takes priority in rating
    
    email_rec = db_session.query(Email).filter(Email.message_id == "<dual-files-id@company.com>").first()
    assert email_rec is not None
    assert len(email_rec.attachments) == 2
    
    # Sort attachments by name to check assertions
    attachments = sorted(email_rec.attachments, key=lambda a: a.filename)
    assert attachments[0].filename == "bad_script.exe"
    assert attachments[0].virus_found is True
    assert attachments[0].threat_label == "Win.Virus.Test-321"
    
    assert attachments[1].filename == "clean_doc.txt"
    assert attachments[1].virus_found is False
