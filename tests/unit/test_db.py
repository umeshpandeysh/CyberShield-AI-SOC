import pytest
import uuid
from datetime import datetime
from backend.app.domain.models import User, Email, Alert

def test_user_model_instantiation():
    user_id = uuid.uuid4()
    user = User(
        id=user_id,
        email="analyst@cybershield.io",
        password_hash="hashed_string_bcrypt",
        role="Analyst_L1",
        is_active=True
    )
    
    assert user.id == user_id
    assert user.email == "analyst@cybershield.io"
    assert user.role == "Analyst_L1"
    assert user.is_active is True

def test_email_model_instantiation():
    email_id = uuid.uuid4()
    email = Email(
        id=email_id,
        message_id="<test-message-123@sender.com>",
        subject="Phishing Alert Test",
        sender="attacker@phish.com",
        recipient="victim@company.com",
        body_text="Verify details here...",
        raw_header="From: attacker@phish.com\nTo: victim@company.com",
        received_at=datetime.utcnow(),
        status="Queued"
    )
    
    assert email.id == email_id
    assert email.message_id == "<test-message-123@sender.com>"
    assert email.sender == "attacker@phish.com"
    assert email.status == "Queued"

def test_alert_model_instantiation():
    alert_id = uuid.uuid4()
    email_id = uuid.uuid4()
    alert = Alert(
        id=alert_id,
        email_id=email_id,
        risk_score=0.92,
        status="OPEN"
    )
    
    assert alert.id == alert_id
    assert alert.email_id == email_id
    assert alert.risk_score == 0.92
    assert alert.status == "OPEN"
