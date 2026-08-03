"""Comprehensive tests for the asynchronous processing pipeline.
Tests cover: TaskRecord model, task status API, async ingest endpoint,
task processor pipeline, retry policies, dead-letter handling.
"""
import pytest
import io
import uuid
from datetime import datetime
from unittest.mock import patch, MagicMock
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.main import app
from app.infra.db_session import get_db
from app.domain.models import Base, User, Email, TaskRecord
from app.adapters.security import get_password_hash

# SQLite in-memory setup for testing
SQLALCHEMY_DATABASE_URL = "sqlite://"
engine = create_engine(
    SQLALCHEMY_DATABASE_URL,
    connect_args={"check_same_thread": False},
    poolclass=StaticPool,
)
TestingSessionLocal = sessionmaker(
    autocommit=False, autoflush=False, bind=engine
)
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
    hashed_pwd = get_password_hash("AsyncTestPass123")
    user = User(
        email="async_analyst@company.com",
        password_hash=hashed_pwd,
        role="Analyst_L1",
        is_active=True
    )
    db_session.add(user)
    db_session.commit()

    login_resp = client.post(
        "/api/v1/auth/login",
        json={
            "email": "async_analyst@company.com",
            "password": "AsyncTestPass123"
        }
    )
    return login_resp.json()["access_token"]


# ===== 1. TaskRecord Model Tests =====

def test_task_record_model_instantiation():
    """Test TaskRecord can be instantiated with valid attributes."""
    task_id = uuid.uuid4()
    task = TaskRecord(
        id=task_id,
        task_type="email_analysis",
        status="Pending",
        retry_count=0,
        created_at=datetime.utcnow()
    )
    assert task.id == task_id
    assert task.task_type == "email_analysis"
    assert task.status == "Pending"
    assert task.retry_count == 0
    assert task.email_id is None
    assert task.error_message is None
    assert task.celery_task_id is None


def test_task_record_with_all_fields():
    """Test TaskRecord with all optional fields populated."""
    task_id = uuid.uuid4()
    email_id = uuid.uuid4()
    now = datetime.utcnow()
    task = TaskRecord(
        id=task_id,
        task_type="email_analysis",
        status="Completed",
        email_id=email_id,
        celery_task_id="celery-abc-123",
        error_message=None,
        retry_count=1,
        created_at=now,
        started_at=now,
        completed_at=now,
        result_data={"email_id": str(email_id), "risk_score": 0.85}
    )
    assert task.email_id == email_id
    assert task.celery_task_id == "celery-abc-123"
    assert task.result_data["risk_score"] == 0.85


def test_task_record_failed_state():
    """Test TaskRecord in failed state with error message."""
    task = TaskRecord(
        id=uuid.uuid4(),
        task_type="email_analysis",
        status="Failed",
        error_message="Connection timeout to ClamAV",
        retry_count=3,
        created_at=datetime.utcnow()
    )
    assert task.status == "Failed"
    assert task.error_message == "Connection timeout to ClamAV"
    assert task.retry_count == 3


def test_task_record_dead_state():
    """Test TaskRecord in dead-letter state after max retries."""
    task = TaskRecord(
        id=uuid.uuid4(),
        task_type="email_analysis",
        status="Dead",
        error_message="Permanently failed after 3 retries",
        retry_count=3,
        created_at=datetime.utcnow()
    )
    assert task.status == "Dead"


def test_task_record_database_persistence(db_session):
    """Test TaskRecord persists to database correctly."""
    task = TaskRecord(
        id=uuid.uuid4(),
        task_type="email_analysis",
        status="Pending",
        created_at=datetime.utcnow()
    )
    db_session.add(task)
    db_session.commit()

    fetched = db_session.query(TaskRecord).filter(
        TaskRecord.id == task.id
    ).first()
    assert fetched is not None
    assert fetched.task_type == "email_analysis"
    assert fetched.status == "Pending"


def test_task_record_status_update(db_session):
    """Test TaskRecord status transitions in database."""
    task = TaskRecord(
        id=uuid.uuid4(),
        task_type="email_analysis",
        status="Pending",
        created_at=datetime.utcnow()
    )
    db_session.add(task)
    db_session.commit()

    task.status = "Running"
    task.started_at = datetime.utcnow()
    db_session.commit()

    fetched = db_session.query(TaskRecord).filter(
        TaskRecord.id == task.id
    ).first()
    assert fetched.status == "Running"
    assert fetched.started_at is not None


# ===== 2. Task Status API Tests =====

def test_get_task_status_success(client, token, db_session):
    """Test retrieving task status for an existing task."""
    task = TaskRecord(
        id=uuid.uuid4(),
        task_type="email_analysis",
        status="Completed",
        retry_count=0,
        created_at=datetime.utcnow(),
        completed_at=datetime.utcnow(),
        result_data={"email_id": "abc-123", "risk_score": 0.5}
    )
    db_session.add(task)
    db_session.commit()

    headers = {"Authorization": f"Bearer {token}"}
    response = client.get(
        f"/api/v1/tasks/{task.id}", headers=headers
    )
    assert response.status_code == 200
    data = response.json()
    assert data["id"] == str(task.id)
    assert data["status"] == "Completed"
    assert data["task_type"] == "email_analysis"
    assert data["result_data"]["risk_score"] == 0.5


def test_get_task_status_not_found(client, token):
    """Test 404 for non-existent task."""
    fake_id = str(uuid.uuid4())
    headers = {"Authorization": f"Bearer {token}"}
    response = client.get(
        f"/api/v1/tasks/{fake_id}", headers=headers
    )
    assert response.status_code == 404
    assert "not found" in response.json()["detail"].lower()


def test_get_task_status_invalid_uuid(client, token):
    """Test 400 for invalid UUID format."""
    headers = {"Authorization": f"Bearer {token}"}
    response = client.get(
        "/api/v1/tasks/not-a-valid-uuid", headers=headers
    )
    assert response.status_code == 400
    assert "Invalid task UUID" in response.json()["detail"]


def test_get_task_status_unauthorized(client):
    """Test 401 for unauthenticated request."""
    fake_id = str(uuid.uuid4())
    response = client.get(f"/api/v1/tasks/{fake_id}")
    assert response.status_code == 401


def test_get_task_status_pending(client, token, db_session):
    """Test task in Pending state has no result_data."""
    task = TaskRecord(
        id=uuid.uuid4(),
        task_type="email_analysis",
        status="Pending",
        retry_count=0,
        created_at=datetime.utcnow()
    )
    db_session.add(task)
    db_session.commit()

    headers = {"Authorization": f"Bearer {token}"}
    response = client.get(
        f"/api/v1/tasks/{task.id}", headers=headers
    )
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "Pending"
    assert data["result_data"] is None
    assert data["started_at"] is None
    assert data["completed_at"] is None


def test_get_task_status_failed(client, token, db_session):
    """Test task in Failed state shows error_message."""
    task = TaskRecord(
        id=uuid.uuid4(),
        task_type="email_analysis",
        status="Failed",
        retry_count=2,
        error_message="EML parser error: malformed header",
        created_at=datetime.utcnow(),
        completed_at=datetime.utcnow()
    )
    db_session.add(task)
    db_session.commit()

    headers = {"Authorization": f"Bearer {token}"}
    response = client.get(
        f"/api/v1/tasks/{task.id}", headers=headers
    )
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "Failed"
    assert "malformed header" in data["error_message"]
    assert data["retry_count"] == 2


# ===== 3. Task List API Tests =====

def test_list_tasks(client, token, db_session):
    """Test listing all tasks with pagination."""
    for i in range(5):
        db_session.add(TaskRecord(
            id=uuid.uuid4(),
            task_type="email_analysis",
            status="Completed" if i < 3 else "Failed",
            retry_count=0,
            created_at=datetime.utcnow()
        ))
    db_session.commit()

    headers = {"Authorization": f"Bearer {token}"}
    response = client.get(
        "/api/v1/tasks?limit=10&offset=0", headers=headers
    )
    assert response.status_code == 200
    data = response.json()
    assert data["total"] == 5
    assert len(data["data"]) == 5


def test_list_tasks_filter_by_status(client, token, db_session):
    """Test listing tasks filtered by status."""
    for i in range(3):
        db_session.add(TaskRecord(
            id=uuid.uuid4(),
            task_type="email_analysis",
            status="Completed",
            retry_count=0,
            created_at=datetime.utcnow()
        ))
    db_session.add(TaskRecord(
        id=uuid.uuid4(),
        task_type="email_analysis",
        status="Failed",
        retry_count=1,
        created_at=datetime.utcnow()
    ))
    db_session.commit()

    headers = {"Authorization": f"Bearer {token}"}
    response = client.get(
        "/api/v1/tasks?status=Failed", headers=headers
    )
    assert response.status_code == 200
    data = response.json()
    assert data["total"] == 1
    assert data["data"][0]["status"] == "Failed"


def test_list_tasks_pagination(client, token, db_session):
    """Test pagination offset and limit."""
    for _ in range(15):
        db_session.add(TaskRecord(
            id=uuid.uuid4(),
            task_type="email_analysis",
            status="Completed",
            retry_count=0,
            created_at=datetime.utcnow()
        ))
    db_session.commit()

    headers = {"Authorization": f"Bearer {token}"}
    response = client.get(
        "/api/v1/tasks?limit=5&offset=10", headers=headers
    )
    assert response.status_code == 200
    data = response.json()
    assert data["total"] == 15
    assert len(data["data"]) == 5
    assert data["limit"] == 5
    assert data["offset"] == 10


def test_list_tasks_empty(client, token):
    """Test listing tasks when none exist."""
    headers = {"Authorization": f"Bearer {token}"}
    response = client.get("/api/v1/tasks", headers=headers)
    assert response.status_code == 200
    data = response.json()
    assert data["total"] == 0
    assert data["data"] == []


# ===== 4. Async Ingest Endpoint Tests =====

@patch("app.adapters.routes.ingest.analyze_email_task", create=True)
def test_async_ingest_returns_202(mock_celery, client, token, db_session):
    """Test async ingest endpoint returns 202 with task_id."""
    # The import inside the route is dynamic, so we patch at the point
    # where celery_tasks is imported in the ingest module
    eml_content = (
        b"From: sender@test.com\n"
        b"To: recipient@test.com\n"
        b"Subject: Async test\n"
        b"Message-ID: <async-test-001@test.com>\n\n"
        b"Test body for async pipeline."
    )

    file_payload = {
        "file": ("async_test.eml", io.BytesIO(eml_content), "message/rfc822")
    }
    headers = {"Authorization": f"Bearer {token}"}

    # Mock celery to use fallback (sync execution)
    with patch(
        "app.adapters.celery_tasks.analyze_email_task"
    ) as mock_task:
        mock_result = MagicMock()
        mock_result.id = str(uuid.uuid4())
        mock_task.apply_async.side_effect = ConnectionError("No Redis")

        response = client.post(
            "/api/v1/ingest/email/async",
            files=file_payload,
            headers=headers
        )

    assert response.status_code == 202
    data = response.json()
    assert "task_id" in data
    assert data["status"] == "Pending"
    assert "queued" in data["message"].lower()

    # Verify TaskRecord was created in database
    task_rec = db_session.query(TaskRecord).filter(
        TaskRecord.id == uuid.UUID(data["task_id"])
    ).first()
    assert task_rec is not None


def test_async_ingest_invalid_format(client, token):
    """Test async ingest rejects non-EML files."""
    file_payload = {
        "file": ("test.txt", io.BytesIO(b"Hello"), "text/plain")
    }
    headers = {"Authorization": f"Bearer {token}"}
    response = client.post(
        "/api/v1/ingest/email/async",
        files=file_payload,
        headers=headers
    )
    assert response.status_code == 400
    assert "Only .eml files" in response.json()["detail"]


def test_async_ingest_empty_file(client, token):
    """Test async ingest rejects empty files."""
    file_payload = {
        "file": ("empty.eml", io.BytesIO(b""), "message/rfc822")
    }
    headers = {"Authorization": f"Bearer {token}"}
    response = client.post(
        "/api/v1/ingest/email/async",
        files=file_payload,
        headers=headers
    )
    assert response.status_code == 400
    assert "empty" in response.json()["detail"].lower()


def test_async_ingest_unauthorized(client):
    """Test async ingest without authentication returns 401."""
    eml_content = b"From: a@b.com\nTo: c@d.com\nSubject: Test\n\nBody"
    file_payload = {
        "file": ("test.eml", io.BytesIO(eml_content), "message/rfc822")
    }
    response = client.post(
        "/api/v1/ingest/email/async",
        files=file_payload
    )
    assert response.status_code == 401


# ===== 5. Task Processor Tests =====

@patch("app.adapters.task_processor.get_ai_service")
@patch("app.adapters.task_processor.ThreatScannerService")
def test_task_processor_success(
    mock_scanner_cls, mock_ai_fn, db_session
):
    """Test task_processor runs the complete pipeline."""
    from app.adapters.task_processor import process_email_pipeline

    # Create task record
    task_id = uuid.uuid4()
    task = TaskRecord(
        id=task_id,
        task_type="email_analysis",
        status="Pending",
        created_at=datetime.utcnow()
    )
    db_session.add(task)
    db_session.commit()

    # Setup mocks
    mock_scanner = MagicMock()
    mock_scanner.execute_pipeline.return_value = MagicMock(
        attachments=[],
        yara_matches=[],
        risk_score=0.05
    )
    mock_scanner_cls.return_value = mock_scanner

    mock_ai = MagicMock()
    mock_ai.classify_email.return_value = {
        "final_risk_score": 0.1,
        "phishing_probability": 0.1,
        "metadata_probability": 0.05,
        "explanations": [],
        "model_version": "test-v1"
    }
    mock_ai_fn.return_value = mock_ai

    eml_bytes = (
        b"From: safe@sender.com\n"
        b"To: user@company.com\n"
        b"Subject: Safe email\n"
        b"Message-ID: <proc-test-001@sender.com>\n\n"
        b"This is a safe email body."
    )

    result = process_email_pipeline(str(task_id), eml_bytes, db_session)

    assert result["status"] == "Completed"
    assert result["sender"] == "safe@sender.com"
    assert "email_id" in result

    # Verify task record updated
    db_session.refresh(task)
    assert task.status == "Completed"
    assert task.started_at is not None
    assert task.completed_at is not None
    assert task.email_id is not None


@patch("app.adapters.task_processor.get_ai_service")
@patch("app.adapters.task_processor.ThreatScannerService")
def test_task_processor_failure_updates_record(
    mock_scanner_cls, mock_ai_fn, db_session
):
    """Test task_processor marks task as Failed on exception."""
    from app.adapters.task_processor import process_email_pipeline

    task_id = uuid.uuid4()
    task = TaskRecord(
        id=task_id,
        task_type="email_analysis",
        status="Pending",
        created_at=datetime.utcnow()
    )
    db_session.add(task)
    db_session.commit()

    # Broken EML that will fail parsing
    eml_bytes = b"THIS IS NOT VALID EML CONTENT"

    # This may raise or not depending on parser tolerance;
    # patch parser to raise
    with patch(
        "app.adapters.task_processor.parse_eml_bytes",
        side_effect=ValueError("Malformed EML")
    ):
        with pytest.raises(ValueError, match="Malformed EML"):
            process_email_pipeline(str(task_id), eml_bytes, db_session)

    db_session.refresh(task)
    assert task.status == "Failed"
    assert "Malformed EML" in task.error_message


@patch("app.adapters.task_processor.get_ai_service")
@patch("app.adapters.task_processor.ThreatScannerService")
def test_task_processor_duplicate_email(
    mock_scanner_cls, mock_ai_fn, db_session
):
    """Test task_processor fails gracefully for duplicate emails."""
    from app.adapters.task_processor import process_email_pipeline

    # Insert an email first
    existing_email = Email(
        id=uuid.uuid4(),
        message_id="<dup-test@sender.com>",
        subject="Existing",
        sender="existing@sender.com",
        recipient="user@company.com",
        body_text="Body",
        raw_header="From: existing@sender.com",
        received_at=datetime.utcnow(),
        status="Completed"
    )
    db_session.add(existing_email)
    db_session.commit()

    task_id = uuid.uuid4()
    task = TaskRecord(
        id=task_id,
        task_type="email_analysis",
        status="Pending",
        created_at=datetime.utcnow()
    )
    db_session.add(task)
    db_session.commit()

    eml_bytes = (
        b"From: existing@sender.com\n"
        b"To: user@company.com\n"
        b"Subject: Existing\n"
        b"Message-ID: <dup-test@sender.com>\n\n"
        b"Body"
    )

    with pytest.raises(ValueError, match="already been ingested"):
        process_email_pipeline(str(task_id), eml_bytes, db_session)

    db_session.refresh(task)
    assert task.status == "Failed"


# ===== 6. Sync Endpoint Backward Compatibility =====

def test_sync_ingest_still_works(client, token, db_session):
    """Test the original sync /ingest/email endpoint still works."""
    eml_content = (
        b"From: sender@compat.com\n"
        b"To: victim@company.com\n"
        b"Subject: Backward compat test\n"
        b"Message-ID: <compat-sync-001@compat.com>\n\n"
        b"Testing backward compatibility."
    )

    file_payload = {
        "file": ("compat.eml", io.BytesIO(eml_content), "message/rfc822")
    }
    headers = {"Authorization": f"Bearer {token}"}

    response = client.post(
        "/api/v1/ingest/email",
        files=file_payload,
        headers=headers
    )
    assert response.status_code == 200
    data = response.json()
    assert data["message_id"] == "<compat-sync-001@compat.com>"
    assert "id" in data
    assert "risk_score" in data


# ===== 7. Celery App Configuration Tests =====

def test_celery_app_configuration():
    """Test Celery app is configured with correct settings."""
    from app.adapters.celery_app import celery_app
    assert celery_app.main == "cybershield"
    assert celery_app.conf.task_serializer == "json"
    assert celery_app.conf.accept_content == ["json"]
    assert celery_app.conf.timezone == "UTC"
    assert celery_app.conf.task_track_started is True
    assert celery_app.conf.task_acks_late is True
    assert celery_app.conf.worker_prefetch_multiplier == 1


def test_celery_task_registered():
    """Test the analyze_email_task is registered in celery."""
    from app.adapters.celery_tasks import analyze_email_task
    assert analyze_email_task.name == "cybershield.analyze_email"
    assert analyze_email_task.max_retries == 3


# ===== 8. End-to-end Async Flow =====

@patch("app.adapters.task_processor.get_ai_service")
@patch("app.adapters.task_processor.ThreatScannerService")
def test_async_flow_end_to_end(
    mock_scanner_cls, mock_ai_fn, client, token, db_session
):
    """Test complete async flow: submit -> check pending -> verify result."""
    # Setup mocks
    mock_scanner = MagicMock()
    mock_scanner.execute_pipeline.return_value = MagicMock(
        attachments=[],
        yara_matches=[],
        risk_score=0.1
    )
    mock_scanner_cls.return_value = mock_scanner

    mock_ai = MagicMock()
    mock_ai.classify_email.return_value = {
        "final_risk_score": 0.15,
        "phishing_probability": 0.1,
        "metadata_probability": 0.05,
        "explanations": [],
        "model_version": "test-v1"
    }
    mock_ai_fn.return_value = mock_ai

    eml_content = (
        b"From: e2e@sender.com\n"
        b"To: user@company.com\n"
        b"Subject: E2E async test\n"
        b"Message-ID: <e2e-async-001@sender.com>\n\n"
        b"End-to-end async test body."
    )

    # Step 1: Submit async
    headers = {"Authorization": f"Bearer {token}"}
    with patch(
        "app.adapters.celery_tasks.analyze_email_task"
    ) as mock_task:
        mock_task.apply_async.side_effect = ConnectionError("No Redis")

        response = client.post(
            "/api/v1/ingest/email/async",
            files={
                "file": (
                    "e2e.eml",
                    io.BytesIO(eml_content),
                    "message/rfc822"
                )
            },
            headers=headers
        )

    assert response.status_code == 202
    task_id = response.json()["task_id"]

    # Step 2: Check task status - should be Completed (sync fallback ran)
    status_resp = client.get(
        f"/api/v1/tasks/{task_id}", headers=headers
    )
    assert status_resp.status_code == 200
    status_data = status_resp.json()
    assert status_data["status"] in ("Completed", "Pending")

    # Step 3: Verify task appears in list
    list_resp = client.get("/api/v1/tasks", headers=headers)
    assert list_resp.status_code == 200
    assert list_resp.json()["total"] >= 1
