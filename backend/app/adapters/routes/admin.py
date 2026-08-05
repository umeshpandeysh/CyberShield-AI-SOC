import uuid
from typing import Optional, List
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session
from pydantic import BaseModel, EmailStr

from app.infra.db_session import get_db
from app.domain.models import User, AuditLog
from app.adapters.routes.auth import get_current_active_user, RoleChecker
from app.adapters.security import get_password_hash

router = APIRouter(prefix="/api/v1/admin", tags=["User & Organization Administration"])
admin_only = RoleChecker(["Admin"])


class CreateUserRequest(BaseModel):
    email: EmailStr
    password: str
    role: str = "Analyst_L1"
    is_active: bool = True


class UpdateUserRequest(BaseModel):
    role: Optional[str] = None
    is_active: Optional[bool] = None


class UserDetailResponse(BaseModel):
    id: str
    email: str
    role: str
    is_active: bool
    created_at: str


class AuditLogResponse(BaseModel):
    id: str
    user_id: Optional[str]
    action: str
    target_entity: str
    details: Optional[str]
    ip_address: Optional[str]
    timestamp: str


@router.get("/users", response_model=List[UserDetailResponse])
def list_users(
    current_user: User = Depends(admin_only),
    db: Session = Depends(get_db)
):
    """Retrieves all user accounts (Admin RBAC)."""
    users = db.query(User).order_by(User.created_at.desc()).all()
    return [
        UserDetailResponse(
            id=str(u.id),
            email=u.email,
            role=u.role,
            is_active=u.is_active,
            created_at=u.created_at.isoformat() + "Z"
        ) for u in users
    ]


@router.post("/users", status_code=status.HTTP_201_CREATED, response_model=UserDetailResponse)
def create_user(
    payload: CreateUserRequest,
    current_user: User = Depends(admin_only),
    db: Session = Depends(get_db)
):
    """Creates a new analyst or administrator user account (Admin RBAC)."""
    valid_roles = ["Admin", "Analyst_L1", "Analyst_L2"]
    if payload.role not in valid_roles:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid role. Must be one of: {', '.join(valid_roles)}"
        )

    existing = db.query(User).filter(User.email == payload.email).first()
    if existing:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="User with this email already exists."
        )

    hashed_pwd = get_password_hash(payload.password)
    user = User(
        id=uuid.uuid4(),
        email=payload.email,
        password_hash=hashed_pwd,
        role=payload.role,
        is_active=payload.is_active
    )
    db.add(user)

    audit = AuditLog(
        id=uuid.uuid4(),
        user_id=current_user.id,
        action="CREATE_USER",
        target_entity="users",
        details=f"Created user {user.email} with role {user.role}"
    )
    db.add(audit)

    try:
        db.commit()
    except Exception as e:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to create user: {str(e)}"
        )

    return UserDetailResponse(
        id=str(user.id),
        email=user.email,
        role=user.role,
        is_active=user.is_active,
        created_at=user.created_at.isoformat() + "Z"
    )


@router.patch("/users/{user_id}", response_model=UserDetailResponse)
def update_user(
    user_id: str,
    payload: UpdateUserRequest,
    current_user: User = Depends(admin_only),
    db: Session = Depends(get_db)
):
    """Updates user role or active status (Admin RBAC)."""
    try:
        u_uuid = uuid.UUID(user_id)
    except ValueError:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid user UUID format")

    user = db.query(User).filter(User.id == u_uuid).first()
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    if payload.role is not None:
        valid_roles = ["Admin", "Analyst_L1", "Analyst_L2"]
        if payload.role not in valid_roles:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid role. Must be one of: {', '.join(valid_roles)}"
            )
        user.role = payload.role

    if payload.is_active is not None:
        user.is_active = payload.is_active

    audit = AuditLog(
        id=uuid.uuid4(),
        user_id=current_user.id,
        action="UPDATE_USER",
        target_entity="users",
        details=f"Updated user {user.email}: role={user.role}, active={user.is_active}"
    )
    db.add(audit)

    try:
        db.commit()
    except Exception as e:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to update user: {str(e)}"
        )

    return UserDetailResponse(
        id=str(user.id),
        email=user.email,
        role=user.role,
        is_active=user.is_active,
        created_at=user.created_at.isoformat() + "Z"
    )


@router.get("/audit-logs", response_model=List[AuditLogResponse])
def list_audit_logs(
    action: Optional[str] = Query(None),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    """Retrieves paginated immutable audit logs."""
    query = db.query(AuditLog)
    if action:
        query = query.filter(AuditLog.action == action)

    logs = query.order_by(AuditLog.timestamp.desc()).limit(limit).offset(offset).all()
    return [
        AuditLogResponse(
            id=str(l.id),
            user_id=str(l.user_id) if l.user_id else None,
            action=l.action,
            target_entity=l.target_entity,
            details=l.details,
            ip_address=l.ip_address,
            timestamp=l.timestamp.isoformat() + "Z"
        ) for l in logs
    ]
