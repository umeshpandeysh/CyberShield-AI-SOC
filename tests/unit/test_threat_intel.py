import pytest
import uuid
import urllib.parse
from datetime import datetime
from unittest.mock import patch, MagicMock
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.main import app
from app.infra.db_session import get_db
from app.domain.models import Base, User, Email, Alert, ThreatIntelRecord, AuditLog
from app.adapters.security import get_password_hash
from app.adapters.threat_intel_service import ThreatIntelService, classify_and_validate_ioc
from app.adapters.threat_intel_providers import (
    ProviderManager, BaseProvider, ProviderResult, CircuitBreaker, CircuitState
)

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
    hashed_pwd = get_password_hash("ThreatIntelPass123!")
    user = User(
        email="ti_analyst@cybershield.io",
        password_hash=hashed_pwd,
        role="Analyst_L1",
        is_active=True
    )
    db_session.add(user)
    db_session.commit()

    login_resp = client.post(
        "/api/v1/auth/login",
        json={"email": "ti_analyst@cybershield.io", "password": "ThreatIntelPass123!"}
    )
    return login_resp.json()["access_token"], user


# ===== 1. IOC Classification & Validation Tests =====

def test_classify_and_validate_ioc_valid_types():
    assert classify_and_validate_ioc("http://phish-test.com/login") == "url"
    assert classify_and_validate_ioc("bad-domain.com") == "domain"
    assert classify_and_validate_ioc("192.168.1.50") == "ip"
    assert classify_and_validate_ioc("attacker@evil.com") == "email"
    assert classify_and_validate_ioc("d41d8cd98f00b204e9800998ecf8427e") == "md5"
    assert classify_and_validate_ioc("da39a3ee5e6b4b0d3255bfef95601890afd80709") == "sha1"
    assert classify_and_validate_ioc("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855") == "sha256"


def test_classify_and_validate_ioc_invalid():
    with pytest.raises(ValueError, match="Malformed or unsupported"):
        classify_and_validate_ioc("not_an_ioc_123")

    with pytest.raises(ValueError, match="non-empty string"):
        classify_and_validate_ioc("")


# ===== 2. Provider Abstraction & Circuit Breaker Tests =====

def test_circuit_breaker_behavior():
    cb = CircuitBreaker(failure_threshold=2, recovery_timeout=0.1)
    assert cb.can_execute() is True
    assert cb.state == CircuitState.CLOSED

    cb.record_failure()
    assert cb.state == CircuitState.CLOSED

    cb.record_failure()
    assert cb.state == CircuitState.OPEN
    assert cb.can_execute() is False

    # Wait for recovery timeout
    import time
    time.sleep(0.15)
    assert cb.can_execute() is True
    assert cb.state == CircuitState.HALF_OPEN

    cb.record_success()
    assert cb.state == CircuitState.CLOSED


def test_provider_manager_health():
    pm = ProviderManager()
    status_list = pm.get_health_status()
    assert len(status_list) >= 5
    provider_names = [p["provider"] for p in status_list]
    assert "virustotal" in provider_names
    assert "abuseipdb" in provider_names
    assert "urlhaus" in provider_names
    assert "otx" in provider_names
    assert "openphish" in provider_names


# ===== 3. Threat Intel Service & Caching Tests =====

def test_threat_intel_service_caching():
    svc = ThreatIntelService()
    svc.clear_cache()

    # First query -> Cache miss
    res1 = svc.enrich_ioc("http://phish-test.com/login")
    assert svc.stats["cache_misses"] == 1
    assert svc.stats["cache_hits"] == 0
    assert res1["overall_verdict"] == "malicious"

    # Second query -> Cache hit
    res2 = svc.enrich_ioc("http://phish-test.com/login")
    assert svc.stats["cache_hits"] == 1
    assert res2 == res1

    # Force refresh -> Cache miss
    res3 = svc.enrich_ioc("http://phish-test.com/login", force_refresh=True)
    assert svc.stats["cache_misses"] == 2


def test_conflicting_provider_responses_aggregation():
    svc = ThreatIntelService()
    # IP indicator queries virustotal, abuseipdb, otx
    res = svc.enrich_ioc("192.168.99.1")
    assert "overall_verdict" in res
    assert "confirming_malicious_providers" in res
    assert len(res["providers"]) >= 1


def test_threat_intel_service_db_persistence(db_session):
    svc = ThreatIntelService()
    svc.enrich_ioc("evil-domain.com", db=db_session)

    records = db_session.query(ThreatIntelRecord).filter(
        ThreatIntelRecord.ioc == "evil-domain.com"
    ).all()
    assert len(records) > 0
    assert any(r.provider == "virustotal" for r in records)


# ===== 4. Alert Risk Escalation Tests =====

def test_alert_enrichment_escalation(db_session):
    # Create Email & Alert
    email = Email(
        id=uuid.uuid4(),
        message_id="<phish-alert-msg@evil.com>",
        sender="phisher@evil.com",
        recipient="victim@company.com",
        subject="Urgent Account Verification",
        raw_header="From: phisher@evil.com",
        received_at=datetime.utcnow(),
        status="Completed"
    )
    alert = Alert(
        id=uuid.uuid4(),
        email_id=email.id,
        risk_score=0.60,
        status="OPEN"
    )
    db_session.add(email)
    db_session.add(alert)
    db_session.commit()

    svc = ThreatIntelService()
    batch_res = svc.enrich_batch(
        iocs=["http://phish-site.com/login", "evil-domain.com"],
        db=db_session,
        alert_id=str(alert.id)
    )

    assert batch_res["alert_updated"] is True
    assert batch_res["new_alert_risk_score"] > 0.60

    db_session.refresh(alert)
    assert alert.risk_score >= 0.90


# ===== 5. REST API Endpoints Tests =====

def test_get_single_ioc_enrichment_api(client, token_and_user):
    token, _ = token_and_user
    headers = {"Authorization": f"Bearer {token}"}

    # URL encoded string
    ioc_url = urllib.parse.quote("http://phish-test-site.com/verify", safe="")
    resp = client.get(f"/api/v1/threat-intel/ioc/{ioc_url}", headers=headers)
    assert resp.status_code == 200
    data = resp.json()
    assert data["ioc"] == "http://phish-test-site.com/verify"
    assert data["ioc_type"] == "url"
    assert "overall_verdict" in data
    assert "providers" in data


def test_get_single_ioc_malformed_api(client, token_and_user):
    token, _ = token_and_user
    headers = {"Authorization": f"Bearer {token}"}

    resp = client.get("/api/v1/threat-intel/ioc/invalid_indicator_$$$", headers=headers)
    assert resp.status_code == 400
    assert "Malformed or unsupported" in resp.json()["detail"]


def test_post_batch_enrichment_api(client, token_and_user, db_session):
    token, _ = token_and_user
    headers = {"Authorization": f"Bearer {token}"}

    payload = {
        "iocs": ["http://phish-site.com/login", "192.168.1.10"],
        "force_refresh": True
    }
    resp = client.post("/api/v1/threat-intel/enrich", json=payload, headers=headers)
    assert resp.status_code == 200
    data = resp.json()
    assert data["total_iocs"] == 2
    assert len(data["results"]) == 2


def test_get_provider_health_api(client, token_and_user):
    token, _ = token_and_user
    headers = {"Authorization": f"Bearer {token}"}

    resp = client.get("/api/v1/threat-intel/providers", headers=headers)
    assert resp.status_code == 200
    data = resp.json()
    assert len(data) >= 5
    assert any(p["provider"] == "virustotal" for p in data)


def test_get_cache_status_api(client, token_and_user):
    token, _ = token_and_user
    headers = {"Authorization": f"Bearer {token}"}

    resp = client.get("/api/v1/threat-intel/cache", headers=headers)
    assert resp.status_code == 200
    data = resp.json()
    assert "cache_hits" in data
    assert "cache_misses" in data

    # Clear cache via query param
    clear_resp = client.get("/api/v1/threat-intel/cache?action=clear", headers=headers)
    assert clear_resp.status_code == 200
    assert clear_resp.json()["cached_keys_count"] == 0
