import pytest
import os
import shutil
from unittest.mock import MagicMock, patch
from app.adapters.imap_poller import poll_imap_inbox, INGEST_CACHE_DIR, cache_failed_eml

@pytest.fixture(autouse=True)
def cleanup_cache_dir():
    """Ensures test runs don't leak cached files in local cache directory."""
    if os.path.exists(INGEST_CACHE_DIR):
        shutil.rmtree(INGEST_CACHE_DIR)
    yield
    if os.path.exists(INGEST_CACHE_DIR):
        shutil.rmtree(INGEST_CACHE_DIR)

def test_cache_failed_eml():
    eml_data = b"From: test@sender.com\nSubject: Test Fail Ingestion\n\nBody"
    cache_failed_eml(eml_data, "<msg-id-888@sender.com>")
    
    assert os.path.exists(INGEST_CACHE_DIR)
    files = os.listdir(INGEST_CACHE_DIR)
    assert len(files) == 1
    assert files[0].endswith(".eml")
    
    # Verify file content
    filepath = os.path.join(INGEST_CACHE_DIR, files[0])
    with open(filepath, "rb") as f:
        content = f.read()
    assert content == eml_data

@patch("imaplib.IMAP4_SSL")
@patch("httpx2.post")
def test_poll_imap_inbox_api_down(mock_post, mock_imap_class):
    # Setup IMAP mock
    mock_imap = MagicMock()
    mock_imap_class.return_value = mock_imap
    
    mock_imap.search.return_value = ("OK", [b"1"])
    mock_imap.fetch.return_value = ("OK", [(None, b"From: sender@domain.com\nSubject: Urgent\n\nBody")])
    
    # Simulate API down
    mock_post.side_effect = Exception("API connection refused")
    
    with patch("app.infra.config.settings.MAIL_INBOX_IMAP_SERVER", "imap.test.com"), \
         patch("app.infra.config.settings.MAIL_INBOX_USER", "user@test.com"):
         
        poll_imap_inbox("http://localhost:8000/api/v1/ingest/email", "mock_token")
        
    # Check that EML was cached to disk
    assert os.path.exists(INGEST_CACHE_DIR)
    files = os.listdir(INGEST_CACHE_DIR)
    assert len(files) == 1
