import os
import time
import imaplib
import logging
import httpx2
from typing import Optional

from app.infra.config import settings

logger = logging.getLogger("imap_poller")

# Directory to cache EMLs locally if the backend server is unreachable
INGEST_CACHE_DIR = os.getenv("INGEST_CACHE_DIR", "data/ingest_cache")

def cache_failed_eml(eml_bytes: bytes, message_id: str):
    """Caches EML payload locally on the filesystem to prevent data loss if API is dead."""
    os.makedirs(INGEST_CACHE_DIR, exist_ok=True)
    safe_id = "".join([c for c in message_id if c.isalnum() or c in ("-", "_")]) or "cached_mail"
    cache_path = os.path.join(INGEST_CACHE_DIR, f"{safe_id}_{int(time.time())}.eml")
    try:
        with open(cache_path, "wb") as f:
            f.write(eml_bytes)
        logger.info(f"Cached raw email to {cache_path} due to backend API outage.")
    except Exception as e:
        logger.error(f"Failed to write EML cache: {str(e)}")

def process_cached_emails(backend_url: str, token: str):
    """Attempts to forward any locally cached EMLs back to the ingestion API when online."""
    if not os.path.exists(INGEST_CACHE_DIR):
        return
        
    cached_files = [f for f in os.listdir(INGEST_CACHE_DIR) if f.endswith(".eml")]
    if not cached_files:
        return
        
    logger.info(f"Found {len(cached_files)} cached emails. Attempting forward...")
    headers = {"Authorization": f"Bearer {token}"}
    
    for file in cached_files:
        path = os.path.join(INGEST_CACHE_DIR, file)
        try:
            with open(path, "rb") as f:
                eml_bytes = f.read()
                
            files = {"file": (file, eml_bytes, "message/rfc822")}
            r = httpx2.post(backend_url, files=files, headers=headers, timeout=10.0)
            
            if r.status_code in (202, 200) or "already been ingested" in r.text:
                os.remove(path)
                logger.info(f"Successfully processed cached email {file}.")
        except Exception as e:
            logger.warning(f"Could not forward cached email {file}: {str(e)}")
            break  # Backend still down

def poll_imap_inbox(backend_url: str, token: str):
    """Connects to the IMAP server, polls for UNSEEN messages, and forwards them to API."""
    if not settings.MAIL_INBOX_IMAP_SERVER or not settings.MAIL_INBOX_USER:
        logger.info("IMAP settings not fully configured. Skipping mail poll.")
        return
        
    try:
        # Connect IMAP over TLS
        imap = imaplib.IMAP4_SSL(
            settings.MAIL_INBOX_IMAP_SERVER, 
            settings.MAIL_INBOX_PORT
        )
        imap.login(settings.MAIL_INBOX_USER, settings.MAIL_INBOX_PASSWORD)
        imap.select("INBOX")
        
        # Search for unseen messages
        status, response = imap.search(None, "UNSEEN")
        if status != "OK":
            logger.error("Failed to query mailbox status.")
            return
            
        email_ids = response[0].split()
        logger.info(f"Discovered {len(email_ids)} unread emails to ingest.")
        
        headers = {"Authorization": f"Bearer {token}"}
        
        for e_id in email_ids:
            # Fetch raw RFC822 message payload
            fetch_status, fetch_data = imap.fetch(e_id, "(RFC822)")
            if fetch_status != "OK" or not fetch_data:
                logger.warning(f"Failed to fetch raw content for message {e_id}.")
                continue
                
            raw_email_bytes = fetch_data[0][1]
            message_id = f"imap_{e_id.decode()}"
            
            # Post EML to API
            files = {"file": (f"{message_id}.eml", raw_email_bytes, "message/rfc822")}
            try:
                r = httpx2.post(backend_url, files=files, headers=headers, timeout=10.0)
                if r.status_code not in (202, 200):
                    logger.error(f"Ingestion endpoint returned error {r.status_code}: {r.text}")
                    cache_failed_eml(raw_email_bytes, message_id)
            except Exception as e:
                logger.error(f"Backend API unreachable: {str(e)}")
                cache_failed_eml(raw_email_bytes, message_id)
                
        imap.logout()
    except Exception as e:
        logger.error(f"IMAP server polling failed: {str(e)}")
