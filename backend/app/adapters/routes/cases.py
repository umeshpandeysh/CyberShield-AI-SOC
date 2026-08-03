import uuid
from datetime import datetime
from typing import Optional, List
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session
from pydantic import BaseModel

from app.infra.db_session import get_db
from app.domain.models import (
    User, Alert, Case, CaseNote, CaseEvent,
    CaseEvidence, AuditLog
)
from app.adapters.routes.auth import (
    get_current_active_user, RoleChecker
)

router = APIRouter(prefix="/api/v1/cases", tags=["Case Management"])

# RBAC role sets
ANALYST_ROLES = ["Admin", "Analyst_L1", "Analyst_L2"]
MANAGER_ROLES = ["Admin", "Analyst_L2"]

# Valid enumerations
VALID_SEVERITIES = ["Critical", "High", "Medium", "Low", "Informational"]
VALID_STATUSES = [
    "Open", "Investigating", "Containment",
    "Eradication", "Recovery", "Closed"
]
VALID_EVIDENCE_TYPES = [
    "email", "attachment", "url", "ioc",
    "log", "screenshot", "network_capture", "other"
]


# --- Request Schemas ---
class CreateCaseRequest(BaseModel):
    title: str
    description: Optional[str] = None
    severity: str = "Medium"
    alert_id: Optional[str] = None
    assigned_to: Optional[str] = None
    tags: Optional[str] = None


class UpdateCaseRequest(BaseModel):
    title: Optional[str] = None
    description: Optional[str] = None
    severity: Optional[str] = None
    status: Optional[str] = None
    assigned_to: Optional[str] = None
    tags: Optional[str] = None


class AddNoteRequest(BaseModel):
    content: str


class AddEvidenceRequest(BaseModel):
    evidence_type: str
    reference_id: Optional[str] = None
    description: str


# --- Response Schemas ---
class CaseSummaryResponse(BaseModel):
    id: str
    title: str
    severity: str
    status: str
    assigned_to: Optional[str]
    created_at: str
    updated_at: str
    tags: Optional[str]
    alert_id: Optional[str]


class PaginatedCasesResponse(BaseModel):
    data: List[CaseSummaryResponse]
    total: int
    limit: int
    offset: int


class NoteResponse(BaseModel):
    id: str
    content: str
    author_id: Optional[str]
    created_at: str


class EventResponse(BaseModel):
    id: str
    event_type: str
    description: str
    actor_id: Optional[str]
    timestamp: str
    metadata_json: Optional[dict]


class EvidenceResponse(BaseModel):
    id: str
    evidence_type: str
    reference_id: Optional[str]
    description: str
    added_by: Optional[str]
    added_at: str


# --- Helper Functions ---

def _log_audit(db, user_id, action, details):
    """Create an audit log entry."""
    db.add(AuditLog(
        id=uuid.uuid4(),
        user_id=user_id,
        action=action,
        target_entity="cases",
        details=details
    ))


def _add_event(db, case_id, actor_id, event_type, description,
               metadata=None):
    """Add a timeline event to a case."""
    db.add(CaseEvent(
        id=uuid.uuid4(),
        case_id=case_id,
        actor_id=actor_id,
        event_type=event_type,
        description=description,
        metadata_json=metadata,
        timestamp=datetime.utcnow()
    ))


def _parse_uuid(value, field_name="ID"):
    """Parse and validate a UUID string."""
    try:
        return uuid.UUID(value)
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid {field_name} UUID format"
        )


def _get_case_or_404(db, case_uuid):
    """Fetch a case by UUID or raise 404."""
    case = db.query(Case).filter(Case.id == case_uuid).first()
    if not case:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Case not found"
        )
    return case


# --- Routes ---

@router.post("", status_code=status.HTTP_201_CREATED)
def create_case(
    payload: CreateCaseRequest,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    """Creates a new SOC investigation case."""
    if payload.severity not in VALID_SEVERITIES:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=(
                f"Invalid severity. Must be one of: "
                f"{', '.join(VALID_SEVERITIES)}"
            )
        )

    if not payload.title or not payload.title.strip():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Case title is required"
        )

    alert_uuid = None
    if payload.alert_id:
        alert_uuid = _parse_uuid(payload.alert_id, "alert_id")
        alert = db.query(Alert).filter(
            Alert.id == alert_uuid
        ).first()
        if not alert:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Alert not found"
            )

    assigned_uuid = None
    if payload.assigned_to:
        assigned_uuid = _parse_uuid(
            payload.assigned_to, "assigned_to"
        )
        assignee = db.query(User).filter(
            User.id == assigned_uuid
        ).first()
        if not assignee:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Assignee user not found"
            )

    case = Case(
        id=uuid.uuid4(),
        title=payload.title.strip(),
        description=payload.description,
        severity=payload.severity,
        status="Open",
        alert_id=alert_uuid,
        assigned_to=assigned_uuid,
        created_by=current_user.id,
        tags=payload.tags,
        created_at=datetime.utcnow()
    )
    db.add(case)

    _add_event(
        db, case.id, current_user.id,
        "CASE_CREATED",
        f"Case '{case.title}' created with severity {case.severity}"
    )
    _log_audit(
        db, current_user.id, "CREATE_CASE",
        f"Created case '{case.title}' (severity={case.severity})"
    )

    try:
        db.commit()
    except Exception as e:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to create case: {str(e)}"
        )

    return {
        "id": str(case.id),
        "title": case.title,
        "severity": case.severity,
        "status": case.status,
        "created_at": case.created_at.isoformat() + "Z"
    }


@router.get("", response_model=PaginatedCasesResponse)
def list_cases(
    status_filter: Optional[str] = Query(
        None, alias="status"
    ),
    severity: Optional[str] = Query(None),
    assigned_to: Optional[str] = Query(None),
    tag: Optional[str] = Query(None),
    search: Optional[str] = Query(None),
    sort_by: Optional[str] = Query(
        "created_at", regex="^(created_at|updated_at|severity)$"
    ),
    sort_order: Optional[str] = Query(
        "desc", regex="^(asc|desc)$"
    ),
    limit: int = Query(20, ge=1, le=100),
    offset: int = Query(0, ge=0),
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    """Retrieves paginated cases with filtering and sorting."""
    query = db.query(Case)

    if status_filter:
        query = query.filter(Case.status == status_filter)
    if severity:
        query = query.filter(Case.severity == severity)
    if assigned_to:
        a_uuid = _parse_uuid(assigned_to, "assigned_to")
        query = query.filter(Case.assigned_to == a_uuid)
    if tag:
        query = query.filter(Case.tags.contains(tag))
    if search:
        query = query.filter(
            Case.title.ilike(f"%{search}%")
        )

    total = query.count()

    # Sorting
    sort_col = getattr(Case, sort_by, Case.created_at)
    if sort_order == "asc":
        query = query.order_by(sort_col.asc())
    else:
        query = query.order_by(sort_col.desc())

    cases = query.limit(limit).offset(offset).all()

    data = []
    for c in cases:
        data.append(CaseSummaryResponse(
            id=str(c.id),
            title=c.title,
            severity=c.severity,
            status=c.status,
            assigned_to=str(c.assigned_to) if c.assigned_to else None,
            created_at=c.created_at.isoformat() + "Z",
            updated_at=c.updated_at.isoformat() + "Z",
            tags=c.tags,
            alert_id=str(c.alert_id) if c.alert_id else None
        ))

    return PaginatedCasesResponse(
        data=data, total=total, limit=limit, offset=offset
    )


@router.get("/{case_id}")
def get_case_detail(
    case_id: str,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    """Returns full case details including notes, events, evidence."""
    case_uuid = _parse_uuid(case_id, "case_id")
    case = _get_case_or_404(db, case_uuid)

    notes = [
        NoteResponse(
            id=str(n.id), content=n.content,
            author_id=str(n.author_id) if n.author_id else None,
            created_at=n.created_at.isoformat() + "Z"
        ) for n in case.notes
    ]

    events = [
        EventResponse(
            id=str(e.id), event_type=e.event_type,
            description=e.description,
            actor_id=str(e.actor_id) if e.actor_id else None,
            timestamp=e.timestamp.isoformat() + "Z",
            metadata_json=e.metadata_json
        ) for e in case.events
    ]

    evidence = [
        EvidenceResponse(
            id=str(ev.id), evidence_type=ev.evidence_type,
            reference_id=ev.reference_id,
            description=ev.description,
            added_by=str(ev.added_by) if ev.added_by else None,
            added_at=ev.added_at.isoformat() + "Z"
        ) for ev in case.evidence_items
    ]

    alert_summary = None
    if case.alert:
        alert_summary = {
            "id": str(case.alert.id),
            "risk_score": case.alert.risk_score,
            "status": case.alert.status
        }

    return {
        "id": str(case.id),
        "title": case.title,
        "description": case.description,
        "severity": case.severity,
        "status": case.status,
        "assigned_to": (
            str(case.assigned_to) if case.assigned_to else None
        ),
        "created_by": (
            str(case.created_by) if case.created_by else None
        ),
        "created_at": case.created_at.isoformat() + "Z",
        "updated_at": case.updated_at.isoformat() + "Z",
        "closed_at": (
            case.closed_at.isoformat() + "Z"
            if case.closed_at else None
        ),
        "tags": case.tags,
        "alert": alert_summary,
        "notes": [n.dict() for n in notes],
        "timeline": [e.dict() for e in events],
        "evidence": [ev.dict() for ev in evidence]
    }


@router.patch("/{case_id}")
def update_case(
    case_id: str,
    payload: UpdateCaseRequest,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    """Updates case fields and logs changes to audit trail."""
    case_uuid = _parse_uuid(case_id, "case_id")
    case = _get_case_or_404(db, case_uuid)

    changes = []

    if payload.title is not None:
        if not payload.title.strip():
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Title cannot be empty"
            )
        old = case.title
        case.title = payload.title.strip()
        changes.append(f"title: '{old}' -> '{case.title}'")

    if payload.description is not None:
        case.description = payload.description
        changes.append("description updated")

    if payload.severity is not None:
        if payload.severity not in VALID_SEVERITIES:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=(
                    f"Invalid severity. Must be one of: "
                    f"{', '.join(VALID_SEVERITIES)}"
                )
            )
        old = case.severity
        case.severity = payload.severity
        changes.append(f"severity: {old} -> {case.severity}")

    if payload.status is not None:
        if payload.status not in VALID_STATUSES:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=(
                    f"Invalid status. Must be one of: "
                    f"{', '.join(VALID_STATUSES)}"
                )
            )
        old = case.status
        case.status = payload.status
        changes.append(f"status: {old} -> {case.status}")
        if payload.status == "Closed":
            case.closed_at = datetime.utcnow()

    if payload.assigned_to is not None:
        a_uuid = _parse_uuid(payload.assigned_to, "assigned_to")
        assignee = db.query(User).filter(
            User.id == a_uuid
        ).first()
        if not assignee:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Assignee user not found"
            )
        case.assigned_to = a_uuid
        changes.append(f"assigned_to: {assignee.email}")

    if payload.tags is not None:
        case.tags = payload.tags
        changes.append("tags updated")

    if not changes:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No fields to update"
        )

    _add_event(
        db, case.id, current_user.id,
        "CASE_UPDATED",
        "; ".join(changes)
    )
    _log_audit(
        db, current_user.id, "UPDATE_CASE",
        f"Case {case.id}: {'; '.join(changes)}"
    )

    try:
        db.commit()
    except Exception as e:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to update case: {str(e)}"
        )

    return {
        "id": str(case.id),
        "title": case.title,
        "severity": case.severity,
        "status": case.status,
        "updated_at": case.updated_at.isoformat() + "Z",
        "changes": changes
    }


# --- Notes ---

@router.post("/{case_id}/notes", status_code=status.HTTP_201_CREATED)
def add_note(
    case_id: str,
    payload: AddNoteRequest,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    """Adds an analyst note to a case."""
    case_uuid = _parse_uuid(case_id, "case_id")
    _get_case_or_404(db, case_uuid)

    if not payload.content or not payload.content.strip():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Note content cannot be empty"
        )

    note = CaseNote(
        id=uuid.uuid4(),
        case_id=case_uuid,
        author_id=current_user.id,
        content=payload.content.strip(),
        created_at=datetime.utcnow()
    )
    db.add(note)

    _add_event(
        db, case_uuid, current_user.id,
        "NOTE_ADDED",
        f"Note added: {payload.content[:100]}..."
    )

    try:
        db.commit()
    except Exception as e:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to add note: {str(e)}"
        )

    return NoteResponse(
        id=str(note.id),
        content=note.content,
        author_id=str(note.author_id),
        created_at=note.created_at.isoformat() + "Z"
    )


@router.get("/{case_id}/notes")
def list_notes(
    case_id: str,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    """Lists all notes for a case."""
    case_uuid = _parse_uuid(case_id, "case_id")
    _get_case_or_404(db, case_uuid)

    notes = db.query(CaseNote).filter(
        CaseNote.case_id == case_uuid
    ).order_by(CaseNote.created_at.desc()).all()

    return [
        NoteResponse(
            id=str(n.id), content=n.content,
            author_id=str(n.author_id) if n.author_id else None,
            created_at=n.created_at.isoformat() + "Z"
        ) for n in notes
    ]


# --- Evidence ---

@router.post(
    "/{case_id}/evidence", status_code=status.HTTP_201_CREATED
)
def add_evidence(
    case_id: str,
    payload: AddEvidenceRequest,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    """Adds evidence to a case."""
    case_uuid = _parse_uuid(case_id, "case_id")
    _get_case_or_404(db, case_uuid)

    if payload.evidence_type not in VALID_EVIDENCE_TYPES:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=(
                f"Invalid evidence_type. Must be one of: "
                f"{', '.join(VALID_EVIDENCE_TYPES)}"
            )
        )

    evidence = CaseEvidence(
        id=uuid.uuid4(),
        case_id=case_uuid,
        evidence_type=payload.evidence_type,
        reference_id=payload.reference_id,
        description=payload.description,
        added_by=current_user.id,
        added_at=datetime.utcnow()
    )
    db.add(evidence)

    _add_event(
        db, case_uuid, current_user.id,
        "EVIDENCE_ADDED",
        f"Evidence ({payload.evidence_type}): {payload.description[:100]}"
    )

    try:
        db.commit()
    except Exception as e:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to add evidence: {str(e)}"
        )

    return EvidenceResponse(
        id=str(evidence.id),
        evidence_type=evidence.evidence_type,
        reference_id=evidence.reference_id,
        description=evidence.description,
        added_by=str(evidence.added_by),
        added_at=evidence.added_at.isoformat() + "Z"
    )


@router.get("/{case_id}/evidence")
def list_evidence(
    case_id: str,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    """Lists all evidence for a case."""
    case_uuid = _parse_uuid(case_id, "case_id")
    _get_case_or_404(db, case_uuid)

    items = db.query(CaseEvidence).filter(
        CaseEvidence.case_id == case_uuid
    ).order_by(CaseEvidence.added_at.desc()).all()

    return [
        EvidenceResponse(
            id=str(ev.id),
            evidence_type=ev.evidence_type,
            reference_id=ev.reference_id,
            description=ev.description,
            added_by=str(ev.added_by) if ev.added_by else None,
            added_at=ev.added_at.isoformat() + "Z"
        ) for ev in items
    ]


# --- Timeline ---

@router.get("/{case_id}/timeline")
def get_timeline(
    case_id: str,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    """Returns the full event timeline for a case."""
    case_uuid = _parse_uuid(case_id, "case_id")
    _get_case_or_404(db, case_uuid)

    events = db.query(CaseEvent).filter(
        CaseEvent.case_id == case_uuid
    ).order_by(CaseEvent.timestamp.desc()).all()

    return [
        EventResponse(
            id=str(e.id),
            event_type=e.event_type,
            description=e.description,
            actor_id=str(e.actor_id) if e.actor_id else None,
            timestamp=e.timestamp.isoformat() + "Z",
            metadata_json=e.metadata_json
        ) for e in events
    ]
