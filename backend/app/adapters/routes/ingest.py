import os
import uuid
from typing import Annotated
from fastapi import APIRouter, Depends, HTTPException, UploadFile, File, status
from sqlalchemy.orm import Session

from app.infra.db_session import get_db
from app.domain.models import User, Email, Attachment, URLIndicator
from app.adapters.routes.auth import get_current_active_user
from app.adapters.email_parser import parse_eml_bytes
from app.adapters.celery_app import celery_app

from app.adapters.storage import save_attachment_file

router = APIRouter(prefix="/api/v1/ingest", tags=["Ingestion"])

@router.post("/email", status_code=status.HTTP_202_ACCEPTED)
async def ingest_email(
    file: UploadFile = File(...),
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    """Uploads a raw RFC822 (.eml) email file, parses metadata, stores entities in DB, 
    and triggers asynchronous threat scanning.
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
        status="Queued"
    )
    
    db.add(email)
    
    # Create Attachment entities and write payloads to disk
    for att in parsed_data["attachments"]:
        att_id = uuid.uuid4()
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
            file_hash_sha256=att["file_hash_sha256"],
            path_on_disk=path,
            scanning_status="Pending"
        )
        db.add(attachment)
        
    # Create URLIndicator entities
    for ui in parsed_data["urls"]:
        url_ind = URLIndicator(
            id=uuid.uuid4(),
            email_id=email.id,
            url=ui["url"],
            hash_sha256=ui["hash_sha256"],
            status="Unrated"
        )
        db.add(url_ind)
        
    try:
        db.commit()
    except Exception as e:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Database insertion failed: {str(e)}"
        )
        
    # Dispatch Celery async analysis task
    try:
        celery_app.send_task("tasks.analyze_email", args=[str(email.id)])
    except Exception:
        # Log error or allow degraded run: enqueued status in DB is preserved
        pass
        
    return {
        "email_id": str(email.id),
        "message_id": email.message_id,
        "status": "Queued",
        "received_at": email.received_at.isoformat() + "Z"
    }
