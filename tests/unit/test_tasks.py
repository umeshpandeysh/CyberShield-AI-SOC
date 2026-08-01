import pytest
import uuid
from datetime import datetime
from unittest.mock import patch, MagicMock
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.domain.models import Base, Email, Attachment, Alert, YaraMatch
from app.tasks import analyze_email

# SQLite in-memory setup for testing Celery tasks
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

@patch("app.tasks.SessionLocal")
@patch("httpx2.post")
@patch("app.tasks.scan_bytes_clamav")
def test_analyze_email_task_phishing(mock_clamav, mock_post, mock_session_local, db_session):
    # Override SessionLocal to bind to in-memory SQLite
    mock_session_local.return_value = db_session
    
    # Mock AI response
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "is_phishing": True,
        "phishing_probability": 0.88,
        "is_spam": False,
        "spam_probability": 0.05,
        "explanations": [{"token": "verify", "weight": 0.45}]
    }
    mock_post.return_value = mock_resp
    
    # Mock ClamAV response (Clean)
    mock_clamav.return_value = (False, "")
    
    email_id = uuid.uuid4()
    email = Email(
        id=email_id,
        message_id="<task-test-mail-99@attacker.com>",
        sender="attacker99@phish.com",
        recipient="victim@company.com",
        subject="Urgent: Verify your account immediately",
        body_text="Verify details here to avoid suspension.",
        raw_header="Headers",
        received_at=datetime.utcnow(),
        status="Queued"
    )
    db_session.add(email)
    db_session.commit()
    
    # Run the task synchronously
    analyze_email(str(email_id))
    
    # Refresh model
    db_session.refresh(email)
    assert email.status == "Completed"
    
    # Check YARA matching rule created
    yara_matches = db_session.query(YaraMatch).filter(YaraMatch.email_id == email_id).all()
    assert len(yara_matches) > 0
    assert yara_matches[0].rule_name == "Phishing_Suspicious_Keywords"
    
    # Assert Alert generated
    alert = db_session.query(Alert).filter(Alert.email_id == email_id).first()
    assert alert is not None
    assert alert.risk_score >= 0.5
    assert alert.status == "OPEN"
