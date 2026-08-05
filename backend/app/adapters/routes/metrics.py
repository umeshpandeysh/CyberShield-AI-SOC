from datetime import datetime, timedelta
from typing import Dict, Any, List
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from sqlalchemy import func
from pydantic import BaseModel

from app.infra.db_session import get_db
from app.domain.models import User, Alert, Email, Attachment, URLIndicator, YaraMatch, Case
from app.adapters.routes.auth import get_current_active_user

router = APIRouter(prefix="/api/v1/metrics", tags=["Threat Metrics & Analytics"])


class MetricsSummaryResponse(BaseModel):
    statistics: Dict[str, int]
    threat_distribution: Dict[str, int]


class AnalyticsResponse(BaseModel):
    threat_trends_7d: List[Dict[str, Any]]
    top_targeted_recipients: List[Dict[str, Any]]
    top_malicious_domains: List[Dict[str, Any]]
    top_yara_signatures: List[Dict[str, Any]]


@router.get("/summary", response_model=MetricsSummaryResponse)
def get_metrics_summary(
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    """Retrieves security center statistics and threat category distribution for dashboard graphs."""
    now = datetime.utcnow()
    today_start = datetime(now.year, now.month, now.day)

    # 1. Total processed today
    total_processed_today = db.query(Email).filter(Email.received_at >= today_start).count()

    # 2. Unresolved alerts count
    unresolved_alerts_count = db.query(Alert).filter(
        Alert.status.in_(["OPEN", "INVESTIGATING"])
    ).count()

    # 3. Quarantined today
    quarantined_today = db.query(Alert).filter(
        Alert.status == "RESOLVED_QUARANTINED",
        Alert.updated_at >= today_start
    ).count()

    # 4. False positives today
    false_positives_today = db.query(Alert).filter(
        Alert.status == "RESOLVED_FALSE_POSITIVE",
        Alert.updated_at >= today_start
    ).count()

    # Threat Distribution (Phishing, Spam, Malware)
    phishing_count = db.query(Alert).filter(
        Alert.ai_phishing_probability >= 0.50
    ).count()

    spam_count = db.query(Alert).filter(
        Alert.ai_spam_probability >= 0.50,
        Alert.ai_phishing_probability < 0.50
    ).count()

    malware_count = db.query(Attachment).filter(
        Attachment.virus_found == True
    ).count()

    return MetricsSummaryResponse(
        statistics={
            "total_processed_today": total_processed_today,
            "unresolved_alerts_count": unresolved_alerts_count,
            "quarantined_today": quarantined_today,
            "false_positives_today": false_positives_today,
        },
        threat_distribution={
            "phishing": phishing_count,
            "spam": spam_count,
            "malware": malware_count
        }
    )


@router.get("/analytics", response_model=AnalyticsResponse)
def get_analytics_detail(
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    """Retrieves 7-day threat trends, top targeted recipients, top malicious domains, and top YARA hits."""
    now = datetime.utcnow()
    seven_days_ago = now - timedelta(days=7)

    # 7-day trend
    trends = []
    for i in range(6, -1, -1):
        day_date = (now - timedelta(days=i)).date()
        day_start = datetime(day_date.year, day_date.month, day_date.day)
        day_end = day_start + timedelta(days=1)

        ingested = db.query(Email).filter(Email.received_at >= day_start, Email.received_at < day_end).count()
        alerts = db.query(Alert).filter(Alert.created_at >= day_start, Alert.created_at < day_end).count()

        trends.append({
            "date": day_date.isoformat(),
            "ingested_emails": ingested,
            "threat_alerts": alerts
        })

    # Top targeted recipients
    top_recipients_q = db.query(
        Email.recipient, func.count(Email.id).label("count")
    ).group_by(Email.recipient).order_by(func.count(Email.id).desc()).limit(5).all()

    top_recipients = [{"recipient": r[0], "alert_count": r[1]} for r in top_recipients_q]

    # Top YARA signatures
    top_yara_q = db.query(
        YaraMatch.rule_name, func.count(YaraMatch.id).label("count")
    ).group_by(YaraMatch.rule_name).order_by(func.count(YaraMatch.id).desc()).limit(5).all()

    top_yara = [{"rule_name": y[0], "match_count": y[1]} for y in top_yara_q]

    # Top malicious domains
    top_domains_q = db.query(
        URLIndicator.url, func.count(URLIndicator.id).label("count")
    ).filter(URLIndicator.status == "Malicious").group_by(URLIndicator.url).order_by(func.count(URLIndicator.id).desc()).limit(5).all()

    top_domains = [{"url": d[0], "count": d[1]} for d in top_domains_q]

    return AnalyticsResponse(
        threat_trends_7d=trends,
        top_targeted_recipients=top_recipients,
        top_malicious_domains=top_domains,
        top_yara_signatures=top_yara
    )
