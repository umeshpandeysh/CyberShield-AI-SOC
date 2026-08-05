import uuid
from datetime import datetime
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.responses import Response
from sqlalchemy.orm import Session

from app.infra.db_session import get_db
from app.domain.models import User, Case, Alert, Email
from app.adapters.routes.auth import get_current_active_user

router = APIRouter(prefix="/api/v1/reports", tags=["Reporting & PDF Export"])


@router.get("/case/{case_id}")
def generate_case_report(
    case_id: str,
    format: Optional[str] = "json",
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    """Generates an executive SOC incident investigation report for a case."""
    try:
        case_uuid = uuid.UUID(case_id)
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid case UUID format"
        )

    case = db.query(Case).filter(Case.id == case_uuid).first()
    if not case:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Case not found"
        )

    alert = case.alert
    email = alert.email if alert else None

    report_content = {
        "report_id": f"REP-{str(case.id)[:8].upper()}",
        "title": f"INCIDENT INVESTIGATION REPORT: {case.title}",
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "generated_by": current_user.email,
        "case_details": {
            "id": str(case.id),
            "title": case.title,
            "description": case.description,
            "severity": case.severity,
            "status": case.status,
            "created_at": case.created_at.isoformat() + "Z",
            "closed_at": case.closed_at.isoformat() + "Z" if case.closed_at else None,
            "tags": case.tags
        },
        "associated_alert": {
            "id": str(alert.id) if alert else None,
            "risk_score": alert.risk_score if alert else None,
            "status": alert.status if alert else None
        } if alert else None,
        "threat_metadata": {
            "sender": email.sender if email else None,
            "recipient": email.recipient if email else None,
            "subject": email.subject if email else None,
            "received_at": email.received_at.isoformat() + "Z" if email else None
        } if email else None,
        "notes_count": len(case.notes),
        "evidence_count": len(case.evidence_items),
        "timeline_events_count": len(case.events)
    }

    if format == "text" or format == "pdf":
        text_report = (
            f"CYBERSHIELD-AI-SOC EXECUTIVE INCIDENT REPORT\n"
            f"Report ID: {report_content['report_id']}\n"
            f"Generated: {report_content['generated_at']} by {current_user.email}\n"
            f"==========================================================\n\n"
            f"Title: {case.title}\n"
            f"Severity: {case.severity}\n"
            f"Status: {case.status}\n"
            f"Created At: {case.created_at.isoformat()}Z\n"
            f"Description: {case.description or 'N/A'}\n\n"
            f"Threat Overview:\n"
            f"- Sender: {email.sender if email else 'N/A'}\n"
            f"- Recipient: {email.recipient if email else 'N/A'}\n"
            f"- Subject: {email.subject if email else 'N/A'}\n"
            f"- Risk Score: {alert.risk_score if alert else 'N/A'}\n"
            f"==========================================================\n"
        )
        return Response(
            content=text_report,
            media_type="text/plain",
            headers={"Content-Disposition": f"attachment; filename=case_{case.id}_report.txt"}
        )

    return report_content


@router.get("/summary")
def get_executive_summary_report(
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    """Generates an executive SOC threat center summary report."""
    total_emails = db.query(Email).count()
    total_alerts = db.query(Alert).count()
    total_cases = db.query(Case).count()
    open_cases = db.query(Case).filter(Case.status != "Closed").count()

    return {
        "report_title": "CyberShield-AI-SOC Security Operations Summary",
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "generated_by": current_user.email,
        "executive_summary": {
            "total_emails_ingested": total_emails,
            "total_threat_alerts": total_alerts,
            "total_incidents_opened": total_cases,
            "active_unresolved_incidents": open_cases
        }
    }
