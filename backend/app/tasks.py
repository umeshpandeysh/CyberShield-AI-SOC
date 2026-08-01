import os
import uuid
import logging
import httpx2
from celery import shared_task
from sqlalchemy.orm import Session

from app.infra.db_session import SessionLocal
from app.domain.models import Email, Attachment, URLIndicator, YaraMatch, Alert
from app.adapters.scanners import scan_bytes_clamav, YaraScanner
from app.adapters.celery_app import celery_app
from app.infra.config import settings

logger = logging.getLogger("tasks")

# Initialize YARA scanner singleton
yara_scanner = YaraScanner()

@celery_app.task(name="tasks.analyze_email")
def analyze_email(email_id: str):
    """Background task orchestrating threat evaluation: YARA, ClamAV, and ML serving classification."""
    logger.info(f"Starting async analysis for email_id: {email_id}")
    db = SessionLocal()
    
    email = None
    try:
        email = db.query(Email).filter(Email.id == uuid.UUID(email_id)).first()
        if not email:
            logger.error(f"Email with id {email_id} not found.")
            return
            
        email.status = "Processing"
        db.commit()
        
        # --- 1. YARA Signature Matching ---
        combined_text = f"{email.subject or ''} {email.body_text or ''} {email.body_html or ''} {email.raw_header or ''}"
        yara_results = yara_scanner.scan_text(combined_text)
        
        for match in yara_results:
            yara_match = YaraMatch(
                id=uuid.uuid4(),
                email_id=email.id,
                rule_name=match["rule_name"],
                tags=",".join(match["tags"]) if match["tags"] else "",
                matched_strings=match["matched_strings"]
            )
            db.add(yara_match)
            
        # --- 2. ClamAV Malware Scans on Attachments ---
        virus_found_flag = False
        virus_labels = []
        for att in email.attachments:
            att.scanning_status = "Scanning"
            db.commit()
            
            if att.path_on_disk and os.path.exists(att.path_on_disk):
                try:
                    with open(att.path_on_disk, "rb") as f:
                        file_bytes = f.read()
                        
                    is_virus, virus_lbl = scan_bytes_clamav(
                        file_bytes, 
                        settings.CLAMAV_HOST, 
                        settings.CLAMAV_PORT
                    )
                    
                    att.virus_found = is_virus
                    if is_virus:
                        att.threat_label = virus_lbl
                        att.scanning_status = "Infected"
                        virus_found_flag = True
                        virus_labels.append(virus_lbl)
                    else:
                        att.scanning_status = "Clean"
                except Exception as e:
                    logger.error(f"Attachment scan error: {str(e)}")
                    att.scanning_status = "Scan_Failed"
            else:
                att.scanning_status = "Scan_Failed"
                
        # --- 3. ML Inference Query ---
        ai_phishing_prob = 0.0
        ai_spam_prob = 0.0
        
        # AI Engine URL - falls back to localhost if not in compose network
        ai_host = os.getenv("AI_HOST", "ai-engine")
        if ai_host == "ai-engine" and settings.ENV == "development" and not os.path.exists("/.dockerenv"):
            ai_host = "localhost"
            
        ai_url = f"http://{ai_host}:8001/api/v1/classify"
        try:
            r = httpx2.post(
                ai_url,
                json={
                    "email_id": str(email.id),
                    "body": email.body_text or email.subject or "Empty body"
                },
                timeout=5.0
            )
            if r.status_code == 200:
                ai_data = r.json()
                ai_phishing_prob = float(ai_data["phishing_probability"])
                ai_spam_prob = float(ai_data["spam_probability"])
        except Exception as e:
            logger.warning(f"Could not connect to AI inference service: {str(e)}")
            
        # --- 4. Risk Score Consolidation ---
        # Default weight: 60% text model, 40% metadata/signature features
        risk_score = ai_phishing_prob * 0.6
        
        # Add signature components to score
        if len(yara_results) > 0:
            risk_score += 0.25
        if virus_found_flag:
            risk_score += 0.40
        if len(email.urls) > 0:
            risk_score += 0.10
            
        # Clamp value between 0.0 and 1.0
        risk_score = min(max(risk_score, 0.0), 1.0)
        
        # --- 5. Save alert state ---
        email.status = "Completed"
        
        # Create threat Alert if risk score is high or malicious signatures match
        if risk_score >= 0.5 or len(yara_results) > 0 or virus_found_flag:
            alert = Alert(
                id=uuid.uuid4(),
                email_id=email.id,
                risk_score=risk_score,
                status="OPEN"
            )
            db.add(alert)
            
        db.commit()
        logger.info(f"Finished async analysis for email_id: {email_id}. Risk: {risk_score}")
    except Exception as e:
        logger.exception(f"Tasks analyze_email execution failed: {str(e)}")
        if email:
            email.status = "Failed"
            db.commit()
    finally:
        db.close()
