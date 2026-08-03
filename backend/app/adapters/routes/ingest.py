import uuid
import hashlib
from datetime import datetime
from typing import Annotated, List, Optional
from fastapi import APIRouter, Depends, HTTPException, UploadFile, File, status
from sqlalchemy.orm import Session
from pydantic import BaseModel

from app.infra.db_session import get_db
from app.domain.models import (
    User, Email, Attachment, URLIndicator, YaraMatch, Alert, TaskRecord
)
from app.adapters.routes.auth import get_current_active_user
from app.adapters.email_parser import parse_eml_bytes
from app.adapters.storage import save_attachment_file
from app.adapters.ioc_service import IOCExtractionService, ExtractedIOCs
from app.adapters.threat_scanner import ThreatScannerService
from app.adapters.ai_service import get_ai_service

router = APIRouter(prefix="/api/v1/ingest", tags=["Ingestion"])

# --- Response Pydantic Schemas ---
class AttachmentInfo(BaseModel):
    id: str
    filename: str
    file_size: int
    content_type: Optional[str]
    file_hash_sha256: str

class URLInfo(BaseModel):
    id: str
    url: str
    hash_sha256: str

class ParsedEmailResponse(BaseModel):
    id: str
    message_id: str
    sender: str
    recipient: str
    subject: Optional[str]
    received_at: str
    body_text: Optional[str]
    body_html: Optional[str]
    raw_header: str
    size_bytes: int
    attachments: List[AttachmentInfo]
    urls: List[URLInfo]
    indicators: ExtractedIOCs
    risk_score: float

@router.post("/email", status_code=status.HTTP_200_OK, response_model=ParsedEmailResponse)
async def ingest_email(
    file: UploadFile = File(...),
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    """Uploads a raw RFC822 (.eml) email file, parses it, extracts threat IOCs, 
    executes synchronous ClamAV and YARA scans, triggers AI threat classification, 
    persists records in PostgreSQL including Alerts, and returns a structured response.
    """
    if not file.filename.endswith(".eml"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid file format. Only RFC822 (.eml) files are supported."
        )
        
    try:
        eml_bytes = await file.read()
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Could not read uploaded file."
        )
        
    if len(eml_bytes) == 0:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Uploaded file is empty."
        )
        
    # Parse EML contents
    try:
        parsed_data = parse_eml_bytes(eml_bytes)
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"EML parser error: {str(e)}"
        )
        
    # Deduplication check
    existing = db.query(Email).filter(Email.message_id == parsed_data["message_id"]).first()
    if existing:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email with this Message-ID has already been ingested."
        )
        
    # Extract IOCs via the reusable domain service
    iocs = IOCExtractionService.extract_iocs(
        body_text=parsed_data["body_text"],
        body_html=parsed_data["body_html"],
        headers_text=parsed_data["raw_header"],
        attachments=parsed_data["attachments"]
    )
    
    # Run threat scanner pipeline synchronously
    scanner_service = ThreatScannerService()
    scan_report = scanner_service.execute_pipeline(
        subject=parsed_data["subject"],
        body_text=parsed_data["body_text"],
        body_html=parsed_data["body_html"],
        headers=parsed_data["raw_header"],
        attachments=parsed_data["attachments"]
    )

    # Run AI Threat Classification
    ai_service = get_ai_service()
    ai_report = ai_service.classify_email(
        body=parsed_data["body_text"],
        headers=parsed_data["raw_header"],
        attachments=parsed_data["attachments"]
    )
        
    # Create Email entity
    email = Email(
        id=uuid.uuid4(),
        message_id=parsed_data["message_id"],
        subject=parsed_data["subject"],
        sender=parsed_data["sender"],
        recipient=parsed_data["recipient"],
        body_text=parsed_data["body_text"],
        body_html=parsed_data["body_html"],
        raw_header=parsed_data["raw_header"],
        size_bytes=parsed_data["size_bytes"],
        received_at=parsed_data["received_at"],
        status="Completed"
    )
    db.add(email)
    
    # Create Attachment entities and save payloads to secure disk path
    attachments_list = []
    for idx, att in enumerate(parsed_data["attachments"]):
        att_id = uuid.uuid4()
        scan_res = scan_report.attachments[idx]
        
        try:
            path = save_attachment_file(att_id, att["filename"], att["payload"])
        except Exception as e:
            db.rollback()
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Attachment storage failed: {str(e)}"
            )
            
        attachment = Attachment(
            id=att_id,
            email_id=email.id,
            filename=att["filename"],
            file_size=att["file_size"],
            content_type=att["content_type"],
            file_hash_sha256=scan_res.sha256,
            path_on_disk=path,
            scanning_status=scan_res.status,
            virus_found=scan_res.virus_found,
            threat_label=scan_res.threat_label
        )
        db.add(attachment)
        attachments_list.append(AttachmentInfo(
            id=str(att_id),
            filename=att["filename"],
            file_size=att["file_size"],
            content_type=att["content_type"],
            file_hash_sha256=scan_res.sha256
        ))
        
    # Store normalized URLs in database url_indicators table
    urls_list = []
    for url_str in iocs.urls:
        url_id = uuid.uuid4()
        hash_sha256 = hashlib.sha256(url_str.encode()).hexdigest()
        
        url_ind = URLIndicator(
            id=url_id,
            email_id=email.id,
            url=url_str,
            hash_sha256=hash_sha256,
            status="Unrated"
        )
        db.add(url_ind)
        urls_list.append(URLInfo(
            id=str(url_id),
            url=url_str,
            hash_sha256=hash_sha256
        ))
        
    # Store YARA matches in database
    for ym in scan_report.yara_matches:
        yara_match = YaraMatch(
            id=uuid.uuid4(),
            email_id=email.id,
            rule_name=ym.rule_name,
            tags=ym.tags,
            matched_strings={"matches": ym.matched_strings}
        )
        db.add(yara_match)
        
    # Consolidate Risk Score from scanner and AI prediction
    final_risk_score = max(scan_report.risk_score, ai_report["final_risk_score"])

    # Create Alert if threat risk score is elevated (malware, YARA, or AI prediction)
    if final_risk_score >= 0.5:
        alert = Alert(
            id=uuid.uuid4(),
            email_id=email.id,
            risk_score=final_risk_score,
            status="OPEN",
            ai_phishing_probability=ai_report["phishing_probability"],
            ai_spam_probability=ai_report["metadata_probability"],
            ai_explanation={"explanations": ai_report["explanations"]},
            ai_model_version=ai_report["model_version"],
            ai_scanned_at=datetime.utcnow()
        )
        db.add(alert)
        
    try:
        db.commit()
    except Exception as e:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Database insertion failed: {str(e)}"
        )
        
    return ParsedEmailResponse(
        id=str(email.id),
        message_id=email.message_id,
        sender=email.sender,
        recipient=email.recipient,
        subject=email.subject,
        received_at=email.received_at.isoformat() + "Z",
        body_text=email.body_text,
        body_html=email.body_html,
        raw_header=email.raw_header,
        size_bytes=email.size_bytes,
        attachments=attachments_list,
        urls=urls_list,
        indicators=iocs,
        risk_score=final_risk_score
    )


# --- Async Ingest Response Schema ---
class AsyncIngestResponse(BaseModel):
    task_id: str
    status: str
    message: str


@router.post(
    "/email/async",
    status_code=status.HTTP_202_ACCEPTED,
    response_model=AsyncIngestResponse
)
async def ingest_email_async(
    file: UploadFile = File(...),
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    """Uploads a raw RFC822 (.eml) email file and queues it
    for asynchronous processing via Celery. Returns a task ID
    immediately for status tracking.
    """
    if not file.filename.endswith(".eml"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid file format. Only .eml files are supported."
        )

    try:
        eml_bytes = await file.read()
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Could not read uploaded file."
        )

    if len(eml_bytes) == 0:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Uploaded file is empty."
        )

    # Create a TaskRecord to track this job
    task_rec = TaskRecord(
        id=uuid.uuid4(),
        task_type="email_analysis",
        status="Pending",
        created_at=datetime.utcnow()
    )
    db.add(task_rec)
    try:
        db.commit()
    except Exception:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to create task record."
        )

    # Dispatch to Celery
    try:
        from app.adapters.celery_tasks import analyze_email_task
        result = analyze_email_task.apply_async(
            args=[str(task_rec.id), eml_bytes.hex()],
            task_id=str(uuid.uuid4())
        )
        task_rec.celery_task_id = result.id
        db.commit()
    except Exception:
        # If Celery/Redis unavailable, execute synchronously as fallback
        from app.adapters.task_processor import process_email_pipeline
        try:
            process_email_pipeline(str(task_rec.id), eml_bytes, db)
        except Exception as e:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Processing failed: {str(e)}"
            )

    return AsyncIngestResponse(
        task_id=str(task_rec.id),
        status="Pending",
        message="Email queued for asynchronous analysis."
    )

