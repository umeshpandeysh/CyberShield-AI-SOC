import urllib.parse
from typing import Optional, List, Dict, Any
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session
from pydantic import BaseModel

from app.infra.db_session import get_db
from app.domain.models import User
from app.adapters.routes.auth import get_current_active_user
from app.adapters.threat_intel_service import ThreatIntelService

router = APIRouter(prefix="/api/v1/threat-intel", tags=["Threat Intelligence"])

# Shared service instance
threat_intel_service = ThreatIntelService()


# --- Pydantic Schemas ---
class BatchEnrichRequest(BaseModel):
    iocs: List[str]
    alert_id: Optional[str] = None
    force_refresh: bool = False


class ProviderHealthResponse(BaseModel):
    provider: str
    health: str
    circuit_state: str
    supported_types: List[str]
    total_requests: int
    success_requests: int
    failed_requests: int
    consecutive_failures: int


class CacheStatusResponse(BaseModel):
    cache_hits: int
    cache_misses: int
    total_enrichments: int
    cached_keys_count: int


# --- Routes ---

@router.get("/ioc/{value:path}")
def enrich_single_ioc(
    value: str,
    ioc_type: Optional[str] = Query(None),
    force_refresh: bool = Query(False),
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    """Enriches a single IOC indicator (URL, IP, Domain, Hash, Email) across threat intel providers."""
    unquoted_value = urllib.parse.unquote(value)
    try:
        res = threat_intel_service.enrich_ioc(
            ioc_value=unquoted_value,
            explicit_type=ioc_type,
            db=db,
            force_refresh=force_refresh
        )
        return res
    except ValueError as ve:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(ve)
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Threat intelligence enrichment failed: {str(e)}"
        )


@router.post("/enrich", status_code=status.HTTP_200_OK)
def enrich_batch_iocs(
    payload: BatchEnrichRequest,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    """Batch enriches multiple IOC indicators and updates alert risk scores if alert_id is provided."""
    if not payload.iocs or len(payload.iocs) == 0:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="List of IOCs cannot be empty."
        )

    if len(payload.iocs) > 100:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Batch limit exceeded. Maximum 100 IOCs per request."
        )

    try:
        res = threat_intel_service.enrich_batch(
            iocs=payload.iocs,
            db=db,
            alert_id=payload.alert_id,
            force_refresh=payload.force_refresh
        )
        return res
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Batch threat intel enrichment failed: {str(e)}"
        )


@router.get("/providers", response_model=List[ProviderHealthResponse])
def get_provider_health(
    current_user: User = Depends(get_current_active_user)
):
    """Retrieves health status, circuit breaker states, and statistics for all threat intelligence providers."""
    return threat_intel_service.provider_manager.get_health_status()


@router.get("/cache", response_model=CacheStatusResponse)
def get_cache_status(
    action: Optional[str] = Query(None),
    current_user: User = Depends(get_current_active_user)
):
    """Retrieves threat intelligence cache statistics and supports clearing the cache."""
    if action == "clear":
        threat_intel_service.clear_cache()

    return CacheStatusResponse(
        cache_hits=threat_intel_service.stats["cache_hits"],
        cache_misses=threat_intel_service.stats["cache_misses"],
        total_enrichments=threat_intel_service.stats["total_enrichments"],
        cached_keys_count=len(threat_intel_service._in_memory_cache)
    )
