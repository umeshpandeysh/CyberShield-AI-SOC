import uuid
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session
from pydantic import BaseModel

from app.infra.db_session import get_db
from app.domain.models import User, TaskRecord
from app.adapters.routes.auth import get_current_active_user

router = APIRouter(prefix="/api/v1/tasks", tags=["Task Tracking"])


# --- Response Schemas ---
class TaskStatusResponse(BaseModel):
    id: str
    task_type: str
    status: str
    email_id: Optional[str]
    celery_task_id: Optional[str]
    error_message: Optional[str]
    retry_count: int
    created_at: str
    started_at: Optional[str]
    completed_at: Optional[str]
    result_data: Optional[dict]


class TaskListResponse(BaseModel):
    data: list
    total: int
    limit: int
    offset: int


@router.get("/{task_id}", response_model=TaskStatusResponse)
def get_task_status(
    task_id: str,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    """Retrieves the current status and result of an async task."""
    try:
        task_uuid = uuid.UUID(task_id)
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid task UUID format"
        )

    task_rec = db.query(TaskRecord).filter(
        TaskRecord.id == task_uuid
    ).first()
    if not task_rec:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Task not found"
        )

    return TaskStatusResponse(
        id=str(task_rec.id),
        task_type=task_rec.task_type,
        status=task_rec.status,
        email_id=str(task_rec.email_id) if task_rec.email_id else None,
        celery_task_id=task_rec.celery_task_id,
        error_message=task_rec.error_message,
        retry_count=task_rec.retry_count,
        created_at=task_rec.created_at.isoformat() + "Z",
        started_at=(
            task_rec.started_at.isoformat() + "Z"
            if task_rec.started_at else None
        ),
        completed_at=(
            task_rec.completed_at.isoformat() + "Z"
            if task_rec.completed_at else None
        ),
        result_data=task_rec.result_data
    )


@router.get("", response_model=TaskListResponse)
def list_tasks(
    status_filter: Optional[str] = Query(
        None, alias="status"
    ),
    limit: int = Query(20, ge=1, le=100),
    offset: int = Query(0, ge=0),
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    """Retrieves a paginated list of tasks, optionally filtered by status."""
    query = db.query(TaskRecord)
    if status_filter:
        query = query.filter(TaskRecord.status == status_filter)

    total = query.count()
    tasks = query.order_by(
        TaskRecord.created_at.desc()
    ).limit(limit).offset(offset).all()

    data = []
    for t in tasks:
        data.append({
            "id": str(t.id),
            "task_type": t.task_type,
            "status": t.status,
            "email_id": str(t.email_id) if t.email_id else None,
            "retry_count": t.retry_count,
            "created_at": t.created_at.isoformat() + "Z",
            "completed_at": (
                t.completed_at.isoformat() + "Z"
                if t.completed_at else None
            ),
        })

    return TaskListResponse(
        data=data, total=total, limit=limit, offset=offset
    )
