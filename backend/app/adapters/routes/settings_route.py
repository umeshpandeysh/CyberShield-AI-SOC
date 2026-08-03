from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from pydantic import BaseModel

from app.infra.config import settings
from app.domain.models import User, AuditLog
from app.infra.db_session import get_db
from app.adapters.routes.auth import get_current_active_user, RoleChecker

router = APIRouter(prefix="/api/v1/settings", tags=["Settings & Configuration"])
admin_only = RoleChecker(["Admin"])


class SystemSettingsResponse(BaseModel):
    project_name: str
    env: str
    confidence_threshold: float
    threat_intel_ttl: int
    clamav_host: str
    clamav_port: int


class UpdateSettingsRequest(BaseModel):
    confidence_threshold: Optional[float] = None
    threat_intel_ttl: Optional[int] = None


@router.get("", response_model=SystemSettingsResponse)
def get_settings(
    current_user: User = Depends(get_current_active_user)
):
    """Retrieves current security platform settings and detection thresholds."""
    return SystemSettingsResponse(
        project_name=settings.PROJECT_NAME,
        env=settings.ENV,
        confidence_threshold=settings.CONFIDENCE_THRESHOLD,
        threat_intel_ttl=getattr(settings, "THREAT_INTEL_CACHE_TTL", 86400),
        clamav_host=settings.CLAMAV_HOST,
        clamav_port=settings.CLAMAV_PORT
    )


@router.patch("", response_model=SystemSettingsResponse)
def update_settings(
    payload: UpdateSettingsRequest,
    current_user: User = Depends(admin_only),
    db: Session = Depends(get_db)
):
    """Updates security platform detection thresholds and parameters (Admin RBAC)."""
    if payload.confidence_threshold is not None:
        if not (0.0 <= payload.confidence_threshold <= 1.0):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="confidence_threshold must be between 0.0 and 1.0"
            )
        settings.CONFIDENCE_THRESHOLD = payload.confidence_threshold

    if payload.threat_intel_ttl is not None:
        if payload.threat_intel_ttl < 60:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="threat_intel_ttl must be at least 60 seconds"
            )
        settings.THREAT_INTEL_CACHE_TTL = payload.threat_intel_ttl

    import uuid
    audit = AuditLog(
        id=uuid.uuid4(),
        user_id=current_user.id,
        action="UPDATE_SETTINGS",
        target_entity="settings",
        details=f"Updated settings: threshold={settings.CONFIDENCE_THRESHOLD}, ttl={settings.THREAT_INTEL_CACHE_TTL}"
    )
    db.add(audit)
    db.commit()

    return SystemSettingsResponse(
        project_name=settings.PROJECT_NAME,
        env=settings.ENV,
        confidence_threshold=settings.CONFIDENCE_THRESHOLD,
        threat_intel_ttl=settings.THREAT_INTEL_CACHE_TTL,
        clamav_host=settings.CLAMAV_HOST,
        clamav_port=settings.CLAMAV_PORT
    )
