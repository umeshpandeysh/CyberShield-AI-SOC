import re
import hashlib
from email import message_from_bytes
from email.utils import parsedate_to_datetime
from datetime import datetime
from typing import Dict, Any, List

def parse_eml_bytes(eml_bytes: bytes) -> Dict[str, Any]:
    """Parses raw EML bytes and extracts metadata, text, attachments, and URLs."""
    msg = message_from_bytes(eml_bytes)
    
    # Extract headers
    message_id = msg.get("Message-ID", "")
    if not message_id:
        # Fallback to generating a unique message-id if missing
        message_id = f"<{hashlib.md5(eml_bytes).hexdigest()}@cybershield.local>"
        
    subject = msg.get("Subject", "")
    sender = msg.get("From", "")
    recipient = msg.get("To", "")
    
    # Parse received timestamp
    date_str = msg.get("Date")
    received_at = datetime.utcnow()
    if date_str:
        try:
            received_at = parsedate_to_datetime(date_str)
            # Normalize to timezone-naive UTC for DB
            if received_at.tzinfo:
                received_at = received_at.astimezone(datetime.timezone.utc).replace(tzinfo=None)
        except Exception:
            pass  # Fall back to current time
            
    # Gather raw headers
    raw_headers = ""
    for name, value in msg.items():
        raw_headers += f"{name}: {value}\n"
        
    body_text = ""
    body_html = ""
    attachments = []
    
    # Walk email payload parts
    for part in msg.walk():
        # Multitype wrapper skip
        if part.is_multipart():
            continue
            
        content_type = part.get_content_type()
        disposition = str(part.get("Content-Disposition", ""))
        
        # Extract files
        filename = part.get_filename()
        if filename or "attachment" in disposition:
            payload = part.get_payload(decode=True) or b""
            attachments.append({
                "filename": filename or "unnamed_attachment",
                "file_size": len(payload),
                "content_type": content_type,
                "file_hash_sha256": hashlib.sha256(payload).hexdigest(),
                "payload": payload
            })
        else:
            # Extract body text
            payload = part.get_payload(decode=True) or b""
            charset = part.get_content_charset() or "utf-8"
            decoded_text = payload.decode(charset, errors="ignore")
            
            if content_type == "text/plain":
                body_text += decoded_text
            elif content_type == "text/html":
                body_html += decoded_text
                
    # If text is empty and html contains content, strip tags for a fallback text body
    if not body_text and body_html:
        body_text = re.sub(r'<[^>]+>', '', body_html)
        
    # Extract URLs from body text and html
    urls = set()
    combined_bodies = f"{body_text} {body_html}"
    found_urls = re.findall(r'https?://[^\s<>"]+|www\.[^\s<>"]+', combined_bodies)
    for url in found_urls:
        urls.add(url.strip())
        
    url_indicators = []
    for url in urls:
        url_indicators.append({
            "url": url,
            "hash_sha256": hashlib.sha256(url.encode()).hexdigest()
        })
        
    return {
        "message_id": message_id,
        "subject": subject,
        "sender": sender,
        "recipient": recipient,
        "body_text": body_text,
        "body_html": body_html,
        "raw_header": raw_headers,
        "size_bytes": len(eml_bytes),
        "received_at": received_at,
        "attachments": attachments,
        "urls": url_indicators
    }
