import pytest
import io
import uuid
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.main import app
from app.infra.db_session import get_db
from app.domain.models import Base, User, Email
from app.adapters.security import get_password_hash
from app.adapters.ioc_service import IOCExtractionService

# Setup DB for integration tests
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

# --- 1. Test Benign Email ---
def test_ioc_extraction_benign_email(client, token):
    eml_content = (
        b"From: colleague@company.com\n"
        b"To: manager@company.com\n"
        b"Subject: Weekly Sync Meeting\n"
        b"Message-ID: <benign-email-123@company.com>\n"
        b"Content-Type: text/plain\n\n"
        b"Hello, here is the link to our meeting doc: http://internal.company.com/sync\n"
        b"See you at 10 AM."
    )
    
    file_payload = {"file": ("benign.eml", io.BytesIO(eml_content), "message/rfc822")}
    headers = {"Authorization": f"Bearer {token}"}
    
    response = client.post("/api/v1/ingest/email", files=file_payload, headers=headers)
    assert response.status_code == 200
    
    data = response.json()
    indicators = data["indicators"]
    assert "http://internal.company.com/sync" in indicators["urls"]
    assert "internal.company.com" in indicators["domains"]
    assert len(indicators["ips"]) == 0
    assert len(indicators["md5_hashes"]) == 0

# --- 2. Test Phishing Email ---
def test_ioc_extraction_phishing_email(client, token):
    eml_content = (
        b"From: support@paypal-security-update.cc\n"
        b"To: victim@company.com\n"
        b"Subject: Alert: Unauthorized Transaction Detected\n"
        b"Message-ID: <phish-email-999@paypal-security.cc>\n"
        b"Content-Type: text/plain\n\n"
        b"We detected a login from IP: 192.168.4.15.\n"
        b"To verify your identity, send email to abuse@paypal.com and reset password at http://paypal-verif.cc/login.\n"
        b"Reference hash: d41d8cd98f00b204e9800998ecf8427e"
    )
    
    file_payload = {"file": ("phish.eml", io.BytesIO(eml_content), "message/rfc822")}
    headers = {"Authorization": f"Bearer {token}"}
    
    response = client.post("/api/v1/ingest/email", files=file_payload, headers=headers)
    assert response.status_code == 200
    
    data = response.json()
    indicators = data["indicators"]
    assert "http://paypal-verif.cc/login" in indicators["urls"]
    assert "paypal-verif.cc" in indicators["domains"]
    assert "192.168.4.15" in indicators["ips"]
    assert "abuse@paypal.com" in indicators["emails"]
    assert "d41d8cd98f00b204e9800998ecf8427e" in indicators["md5_hashes"]

# --- 3. Test Malformed Email ---
def test_ioc_extraction_malformed_email(client, token):
    # EML content with malformed IPs, malformed URLs and malformed domains
    eml_content = (
        b"From: attacker@malicious.com\n"
        b"To: target@company.com\n"
        b"Subject: Malformed IOCs\n"
        b"Message-ID: <malformed-id-777@malicious.com>\n"
        b"Content-Type: text/plain\n\n"
        b"Invalid IP addresses: 999.999.999.999, 192.168.1.300\n"
        b"Malformed URL: http://[invalid-url]/\n"
        b"Invalid domains: not_a_domain_name, this-is-too-long-" + (b"a" * 300) + b".com"
    )
    
    file_payload = {"file": ("malformed.eml", io.BytesIO(eml_content), "message/rfc822")}
    headers = {"Authorization": f"Bearer {token}"}
    
    response = client.post("/api/v1/ingest/email", files=file_payload, headers=headers)
    assert response.status_code == 200
    
    data = response.json()
    indicators = data["indicators"]
    # Verify malformed IOCs are ignored gracefully
    assert len(indicators["ips"]) == 0
    assert len(indicators["domains"]) == 0

# --- 4. Test Duplicate Indicators ---
def test_ioc_extraction_duplicate_indicators(client, token):
    eml_content = (
        b"From: double@attacker.com\n"
        b"To: target@company.com\n"
        b"Subject: Duplicate test\n"
        b"Message-ID: <duplicate-id-555@attacker.com>\n"
        b"Content-Type: text/plain\n\n"
        b"Click here: http://phish-link.com/reset\n"
        b"I repeat, click here: http://phish-link.com/reset\n"
        b"Connecting from 10.0.0.1 and 10.0.0.1."
    )
    
    file_payload = {"file": ("dup.eml", io.BytesIO(eml_content), "message/rfc822")}
    headers = {"Authorization": f"Bearer {token}"}
    
    response = client.post("/api/v1/ingest/email", files=file_payload, headers=headers)
    assert response.status_code == 200
    
    data = response.json()
    indicators = data["indicators"]
    # Check deduplication has occurred (only one instance returned)
    assert indicators["urls"] == ["http://phish-link.com/reset"]
    assert indicators["ips"] == ["10.0.0.1"]
    assert indicators["domains"] == ["phish-link.com"]

# --- 5. Test Attachment Extraction ---
def test_ioc_extraction_attachment_extraction(client, token):
    # Generate raw EML with a file attachment block
    eml_content = (
        b"From: finance@company.com\n"
        b"To: accounting@company.com\n"
        b"Subject: Invoice file\n"
        b"Message-ID: <invoice-email-444@company.com>\n"
        b"MIME-Version: 1.0\n"
        b"Content-Type: multipart/mixed; boundary=\"boundary\"\n\n"
        b"--boundary\n"
        b"Content-Type: text/plain\n\n"
        b"Please review attachment.\n\n"
        b"--boundary\n"
        b"Content-Type: application/pdf\n"
        b"Content-Disposition: attachment; filename=\"invoice.pdf\"\n"
        b"Content-Transfer-Encoding: base64\n\n"
        b"JVBERi0xLjQKJcOlnwdecwplbmRvYmo=\n"  # Mock PDF base64 bytes
        b"--boundary--"
    )
    
    file_payload = {"file": ("invoice.eml", io.BytesIO(eml_content), "message/rfc822")}
    headers = {"Authorization": f"Bearer {token}"}
    
    response = client.post("/api/v1/ingest/email", files=file_payload, headers=headers)
    assert response.status_code == 200
    
    data = response.json()
    assert len(data["attachments"]) == 1
    assert data["attachments"][0]["filename"] == "invoice.pdf"
    
    indicators = data["indicators"]
    assert "invoice.pdf" in indicators["filenames"]
    # Hashes of attachment payload are generated
    assert len(indicators["sha256_hashes"]) == 1
    assert len(indicators["md5_hashes"]) == 1
    assert len(indicators["sha1_hashes"]) == 1
