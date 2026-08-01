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
from app.domain.models import Base, User, Email, Alert
from app.adapters.security import get_password_hash
from app.adapters.ai_service import get_ai_service

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

# --- 1. Test Model Startup Loading ---
def test_ai_classification_load_once():
    service = get_ai_service()
    assert service.text_model is not None
    assert service.meta_model is not None
    # Singleton check
    service2 = get_ai_service()
    assert service is service2

# --- 2. Test Phishing Prediction and Explainability ---
@patch("app.adapters.threat_scanner.scan_bytes_clamav")
def test_ai_classification_predictions(mock_clamav, client, token, db_session):
    mock_clamav.return_value = (False, "")
    
    # Text with strong phishing keywords matching vectorized bootstrap corpus
    eml_content = (
        b"From: support@paypal-security.cc\n"
        b"To: user@company.com\n"
        b"Subject: Urgent account action required\n"
        b"Message-ID: <ai-predict-test-9@paypal-security.cc>\n"
        b"Content-Type: text/plain\n\n"
        b"verify your account details immediately, urgent secure link action required"
    )
    
    file_payload = {"file": ("phish.eml", io.BytesIO(eml_content), "message/rfc822")}
    headers = {"Authorization": f"Bearer {token}"}
    
    response = client.post("/api/v1/ingest/email", files=file_payload, headers=headers)
    assert response.status_code == 200
    
    # Assert risk score is high due to phishing probability
    data = response.json()
    assert data["risk_score"] >= 0.5
    
    # Verify Alert contains AI analysis and explainability tokens
    email_rec = db_session.query(Email).filter(Email.message_id == "<ai-predict-test-9@paypal-security.cc>").first()
    assert email_rec is not None
    alert_rec = db_session.query(Alert).filter(Alert.email_id == email_rec.id).first()
    assert alert_rec is not None
    assert alert_rec.ai_phishing_probability > 0.5
    assert len(alert_rec.ai_explanation["explanations"]) > 0

# --- 3. Test API Detail Exposure ---
@patch("app.adapters.threat_scanner.scan_bytes_clamav")
def test_ai_classification_get_alert_ai_analysis(mock_clamav, client, token):
    mock_clamav.return_value = (False, "")
    
    eml_content = (
        b"From: support@paypal-security.cc\n"
        b"To: user@company.com\n"
        b"Subject: Urgent account action required\n"
        b"Message-ID: <ai-api-test-88@paypal-security.cc>\n"
        b"Content-Type: text/plain\n\n"
        b"verify your account details immediately, urgent secure link action required"
    )
    
    file_payload = {"file": ("phish.eml", io.BytesIO(eml_content), "message/rfc822")}
    headers = {"Authorization": f"Bearer {token}"}
    
    # Ingest to create alert
    ingest_resp = client.post("/api/v1/ingest/email", files=file_payload, headers=headers)
    assert ingest_resp.status_code == 200
    
    # Get alerts list to retrieve UUID
    list_resp = client.get("/api/v1/alerts", headers=headers)
    alert_uuid = list_resp.json()["data"][0]["id"]
    
    # Fetch details
    detail_resp = client.get(f"/api/v1/alerts/{alert_uuid}", headers=headers)
    assert detail_resp.status_code == 200
    
    detail_data = detail_resp.json()
    assert "ai_analysis" in detail_data
    ai_analysis = detail_data["ai_analysis"]
    assert ai_analysis["phishing_probability"] > 0.5
    assert "verify" in ai_analysis["critical_tokens"] or "account" in ai_analysis["critical_tokens"]

# --- 4. Test Inference Degradation/Exceptions Handling ---
@patch("app.adapters.threat_scanner.scan_bytes_clamav")
def test_ai_classification_degrades_gracefully(mock_clamav, client, token, db_session):
    mock_clamav.return_value = (False, "")
    
    # Access and mock the service predict_proba call to raise an exception
    service = get_ai_service()
    orig_predict_proba = service.text_model.predict_proba
    service.text_model.predict_proba = MagicMock(side_effect=Exception("Classifier weights corrupt"))
    
    try:
        eml_content = (
            b"From: standard@company.com\n"
            b"To: employee@company.com\n"
            b"Subject: Standard query\n"
            b"Message-ID: <ai-fail-test-7@company.com>\n"
            b"Content-Type: text/plain\n\n"
            b"Is the server still running fine?"
        )
        
        file_payload = {"file": ("query.eml", io.BytesIO(eml_content), "message/rfc822")}
        headers = {"Authorization": f"Bearer {token}"}
        
        # Ingestion pipeline should NOT crash and should return 200 OK
        response = client.post("/api/v1/ingest/email", files=file_payload, headers=headers)
        assert response.status_code == 200
        
        data = response.json()
        assert data["risk_score"] == 0.0 # Default fallback score
    finally:
        # Restore mock state
        service.text_model.predict_proba = orig_predict_proba
