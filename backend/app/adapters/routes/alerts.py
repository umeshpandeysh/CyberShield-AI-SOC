import uuid
from typing import Optional, List
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session
from pydantic import BaseModel

from app.infra.db_session import get_db
from app.domain.models import User, Alert, Email, AuditLog
from app.adapters.routes.auth import get_current_active_user, RoleChecker

router = APIRouter(prefix="/api/v1/alerts", tags=["Alerts & Case Management"])

# --- Request / Response Pydantic Schemas ---
class TriageRequest(BaseModel):
    status: str
    assigned_to: Optional[str] = None
    comments: Optional[str] = None

class EmailMetaResponse(BaseModel):
    id: str
    message_id: str
    sender: str
    recipient: str
    subject: Optional[str]
    body_text: Optional[str]
    received_at: str

class AlertSummaryResponse(BaseModel):
    id: str
    email_id: str
    sender: str
    subject: Optional[str]
    risk_score: float
    status: str
    assigned_to: Optional[str]
    created_at: str

class PaginatedAlertsResponse(BaseModel):
    data: List[AlertSummaryResponse]
    total: int
    limit: int
    offset: int

# --- Routes ---

@router.get("", response_model=PaginatedAlertsResponse)
def list_alerts(
    status: Optional[str] = None,
    min_score: Optional[float] = None,
    limit: int = Query(20, ge=1, le=100),
    offset: int = Query(0, ge=0),
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    """Retrieves a paginated list of threat alerts, filterable by status and risk scores."""
    query = db.query(Alert).join(Email)
    
    if status:
        query = query.filter(Alert.status == status)
    if min_score is not None:
        query = query.filter(Alert.risk_score >= min_score)
        
    total = query.count()
    alerts = query.order_by(Alert.risk_score.desc()).limit(limit).offset(offset).all()
    
    data = []
    for alert in alerts:
        data.append(AlertSummaryResponse(
            id=str(alert.id),
            email_id=str(alert.email_id),
            sender=alert.email.sender,
            subject=alert.email.subject,
            risk_score=alert.risk_score,
            status=alert.status,
            assigned_to=str(alert.assigned_to) if alert.assigned_to else None,
            created_at=alert.created_at.isoformat() + "Z"
        ))
        
    return PaginatedAlertsResponse(
        data=data,
        total=total,
        limit=limit,
        offset=offset
    )

@router.get("/{id}")
def get_alert_detail(
    id: str,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    """Returns comprehensive metadata, attachment hashes, and scan results for a specific alert."""
    try:
        alert_uuid = uuid.UUID(id)
    except ValueError:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid alert UUID format")
        
    alert = db.query(Alert).filter(Alert.id == alert_uuid).first()
    if not alert:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Alert not found")
        
    email = alert.email
    
    attachments_data = []
    for att in email.attachments:
        attachments_data.append({
            "id": str(att.id),
            "filename": att.filename,
            "file_size": att.file_size,
            "file_hash_sha256": att.file_hash_sha256,
            "scanning_status": att.scanning_status,
            "virus_found": att.virus_found,
            "threat_label": att.threat_label
        })
        
    urls_data = []
    for ui in email.urls:
        urls_data.append({
            "id": str(ui.id),
            "url": ui.url,
            "vt_positives": ui.vt_positives,
            "vt_total": ui.vt_total,
            "status": ui.status
        })
        
    yara_data = []
    for ym in email.yara_matches:
        yara_data.append({
            "id": str(ym.id),
            "rule_name": ym.rule_name,
            "tags": ym.tags,
            "matched_strings": ym.matched_strings
        })
        
    return {
        "id": str(alert.id),
        "risk_score": alert.risk_score,
        "status": alert.status,
        "assigned_to": str(alert.assigned_to) if alert.assigned_to else None,
        "email": {
            "id": str(email.id),
            "message_id": email.message_id,
            "sender": email.sender,
            "recipient": email.recipient,
            "subject": email.subject,
            "body_text": email.body_text,
            "body_html": email.body_html,
            "raw_header": email.raw_header,
            "received_at": email.received_at.isoformat() + "Z"
        },
        "attachments": attachments_data,
        "urls": urls_data,
        "yara_matches": yara_data
    }

@router.patch("/{id}/triage")
def triage_alert(
    id: str,
    payload: TriageRequest,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    """Updates the workflow status, sets assignments, and commits details to audit logs."""
    try:
        alert_uuid = uuid.UUID(id)
    except ValueError:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid alert UUID format")
        
    alert = db.query(Alert).filter(Alert.id == alert_uuid).first()
    if not alert:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Alert not found")
        
    # Validate status values
    allowed_statuses = ["OPEN", "INVESTIGATING", "RESOLVED_QUARANTINED", "RESOLVED_FALSE_POSITIVE"]
    if payload.status not in allowed_statuses:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid status. Must be one of: {', '.join(allowed_statuses)}"
        )
        
    assigned_user_uuid = None
    if payload.assigned_to:
        try:
            assigned_user_uuid = uuid.UUID(payload.assigned_to)
        except ValueError:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid assignee user UUID format")
            
        assigned_user = db.query(User).filter(User.id == assigned_user_uuid).first()
        if not assigned_user:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Assignee user does not exist")
            
    # Record mutations
    old_status = alert.status
    alert.status = payload.status
    if payload.assigned_to:
        alert.assigned_to = assigned_user_uuid
        
    # Log audit entry
    log_detail = f"Status changed from {old_status} to {payload.status}."
    if payload.comments:
        log_detail += f" Comments: {payload.comments}"
        
    audit_log = AuditLog(
        id=uuid.uuid4(),
        user_id=current_user.id,
        action="TRIAGE_ALERT",
        target_entity="alerts",
        details=log_detail
    )
    db.add(audit_log)
    
    try:
        db.commit()
    except Exception as e:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Triage update failed: {str(e)}"
        )
        
    return {
        "alert_id": str(alert.id),
        "status": alert.status,
        "updated_at": alert.updated_at.isoformat() + "Z",
        "triage_by": str(current_user.id)
    }
