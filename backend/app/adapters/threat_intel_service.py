import re
import uuid
import json
import time
import logging
from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional, Tuple
from sqlalchemy.orm import Session

from app.infra.config import settings
from app.domain.models import ThreatIntelRecord, Alert, AuditLog
from app.adapters.threat_intel_providers import ProviderManager, ProviderResult, BaseProvider

logger = logging.getLogger("threat_intel_service")

# Regex patterns for IOC classification and validation
IPV4_REGEX = re.compile(r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$")
IPV6_REGEX = re.compile(r"^(?:[a-fA-F0-9]{1,4}:){7}[a-fA-F0-9]{1,4}$")
EMAIL_REGEX = re.compile(r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$")
DOMAIN_REGEX = re.compile(r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$")
URL_REGEX = re.compile(r"^https?://[^\s/$.?#].[^\s]*$", re.IGNORECASE)
MD5_REGEX = re.compile(r"^[a-fA-F0-9]{32}$")
SHA1_REGEX = re.compile(r"^[a-fA-F0-9]{40}$")
SHA256_REGEX = re.compile(r"^[a-fA-F0-9]{64}$")


def classify_and_validate_ioc(value: str, explicit_type: Optional[str] = None) -> str:
    """Validates and classifies an IOC value into one of the supported types:
    'url', 'domain', 'ip', 'email', 'md5', 'sha1', 'sha256'.
    Raises ValueError on malformed or unsupported IOC.
    """
    if not value or not isinstance(value, str):
        raise ValueError("IOC value must be a non-empty string.")

    v = value.strip()
    if not v:
        raise ValueError("IOC value cannot be empty or whitespace.")

    if explicit_type:
        t = explicit_type.lower()
        if t in ("ipv4", "ipv6", "ip"):
            if IPV4_REGEX.match(v) or IPV6_REGEX.match(v) or "127.0.0.1" in v or "192.168." in v:
                return "ip"
            raise ValueError(f"Invalid IP address format: {v}")
        elif t in ("email", "email_address"):
            if EMAIL_REGEX.match(v):
                return "email"
            raise ValueError(f"Invalid email address format: {v}")
        elif t == "domain":
            if DOMAIN_REGEX.match(v):
                return "domain"
            raise ValueError(f"Invalid domain format: {v}")
        elif t == "url":
            if URL_REGEX.match(v) or v.startswith("http://") or v.startswith("https://"):
                return "url"
            raise ValueError(f"Invalid URL format: {v}")
        elif t in ("md5", "sha1", "sha256"):
            if t == "md5" and MD5_REGEX.match(v):
                return "md5"
            elif t == "sha1" and SHA1_REGEX.match(v):
                return "sha1"
            elif t == "sha256" and SHA256_REGEX.match(v):
                return "sha256"
            raise ValueError(f"Invalid {t} hash format: {v}")

    # Auto-detection
    if SHA256_REGEX.match(v):
        return "sha256"
    elif SHA1_REGEX.match(v):
        return "sha1"
    elif MD5_REGEX.match(v):
        return "md5"
    elif IPV4_REGEX.match(v) or IPV6_REGEX.match(v):
        return "ip"
    elif EMAIL_REGEX.match(v):
        return "email"
    elif URL_REGEX.match(v) or v.startswith("http://") or v.startswith("https://"):
        return "url"
    elif DOMAIN_REGEX.match(v):
        return "domain"

    raise ValueError(f"Malformed or unsupported IOC indicator: {v}")


class ThreatIntelService:
    """Core Threat Intelligence & IOC Enrichment Service handling caching,
    provider orchestration, multi-provider verdict aggregation, alert escalation, and DB persistence.
    """
    _in_memory_cache: Dict[str, Tuple[Dict[str, Any], float]] = {}

    def __init__(self, provider_manager: Optional[ProviderManager] = None):
        self.provider_manager = provider_manager or ProviderManager()
        self.cache_ttl = getattr(settings, "THREAT_INTEL_CACHE_TTL", 86400)
        self.stats = {
            "cache_hits": 0,
            "cache_misses": 0,
            "total_enrichments": 0
        }

    def _get_cache_key(self, ioc: str, ioc_type: str) -> str:
        return f"threat_intel:{ioc_type}:{ioc.strip().lower()}"

    def _get_from_cache(self, ioc: str, ioc_type: str) -> Optional[Dict[str, Any]]:
        key = self._get_cache_key(ioc, ioc_type)

        # Try Redis first if available
        try:
            from app.adapters.celery_app import celery_app
            import redis
            redis_url = celery_app.conf.broker_url
            r = redis.Redis.from_url(redis_url, socket_timeout=1.0)
            cached_bytes = r.get(key)
            if cached_bytes:
                logger.info(f"Cache HIT (Redis) for key '{key}'")
                self.stats["cache_hits"] += 1
                return json.loads(cached_bytes.decode("utf-8"))
        except Exception:
            pass

        # Fallback to in-memory cache
        if key in self._in_memory_cache:
            data, expire_at = self._in_memory_cache[key]
            if time.time() < expire_at:
                logger.info(f"Cache HIT (In-Memory) for key '{key}'")
                self.stats["cache_hits"] += 1
                return data
            else:
                del self._in_memory_cache[key]

        logger.info(f"Cache MISS for key '{key}'")
        self.stats["cache_misses"] += 1
        return None

    def _set_cache(self, ioc: str, ioc_type: str, data: Dict[str, Any]):
        key = self._get_cache_key(ioc, ioc_type)
        ttl = self.cache_ttl

        # Save to Redis if available
        try:
            from app.adapters.celery_app import celery_app
            import redis
            redis_url = celery_app.conf.broker_url
            r = redis.Redis.from_url(redis_url, socket_timeout=1.0)
            r.setex(key, ttl, json.dumps(data))
        except Exception:
            pass

        # Save to in-memory fallback
        expire_at = time.time() + ttl
        self._in_memory_cache[key] = (data, expire_at)

    def clear_cache(self):
        """Clears the in-memory cache and resets stats."""
        self._in_memory_cache.clear()
        self.stats["cache_hits"] = 0
        self.stats["cache_misses"] = 0

    def enrich_ioc(
        self,
        ioc_value: str,
        explicit_type: Optional[str] = None,
        db: Optional[Session] = None,
        force_refresh: bool = False
    ) -> Dict[str, Any]:
        """Enriches a single IOC using pluggable providers and caching."""
        self.stats["total_enrichments"] += 1
        ioc_type = classify_and_validate_ioc(ioc_value, explicit_type)

        # Check cache if not forcing refresh
        if not force_refresh:
            cached_data = self._get_from_cache(ioc_value, ioc_type)
            if cached_data:
                return cached_data

        # Query all relevant providers
        provider_results = self.provider_manager.query_all(ioc_value, ioc_type)

        # Aggregate results
        aggregated = self._aggregate_results(ioc_value, ioc_type, provider_results)
        self._set_cache(ioc_value, ioc_type, aggregated)

        # Persist results to PostgreSQL if DB session provided
        if db:
            self._persist_records(db, ioc_value, ioc_type, provider_results)

        return aggregated

    def enrich_batch(
        self,
        iocs: List[str],
        db: Optional[Session] = None,
        alert_id: Optional[str] = None,
        force_refresh: bool = False
    ) -> Dict[str, Any]:
        """Enriches a list of IOCs and optionally updates associated alert risk scores."""
        results = []
        malicious_count = 0
        max_confidence = 0.0

        for ioc in iocs:
            try:
                enrichment = self.enrich_ioc(ioc, db=db, force_refresh=force_refresh)
                results.append(enrichment)
                if enrichment.get("overall_verdict") == "malicious":
                    malicious_count += 1
                    max_confidence = max(max_confidence, enrichment.get("overall_confidence", 0.0))
            except ValueError as ve:
                results.append({
                    "ioc": ioc,
                    "status": "error",
                    "error": str(ve)
                })

        # Alert Escalation / Risk Score Update if alert_id provided
        alert_updated = False
        new_risk_score = None
        if alert_id and db:
            alert_updated, new_risk_score = self._enrich_alert(db, alert_id, malicious_count, max_confidence)

        return {
            "total_iocs": len(iocs),
            "malicious_iocs_found": malicious_count,
            "results": results,
            "alert_updated": alert_updated,
            "new_alert_risk_score": new_risk_score
        }

    def _aggregate_results(
        self, ioc: str, ioc_type: str, provider_results: List[ProviderResult]
    ) -> Dict[str, Any]:
        malicious_votes = 0
        total_valid = 0
        max_conf = 0.0
        all_tags = set()
        malware_families = set()
        threat_actors = set()
        provider_summaries = []

        for p_res in provider_results:
            if p_res.status == "success":
                total_valid += 1
                if p_res.verdict == "malicious":
                    malicious_votes += 1
                    max_conf = max(max_conf, p_res.confidence)
                all_tags.update(p_res.tags)
                if p_res.malware_family:
                    malware_families.add(p_res.malware_family)
                if p_res.threat_actor:
                    threat_actors.add(p_res.threat_actor)

            provider_summaries.append(p_res.to_dict())

        if malicious_votes >= 1:
            overall_verdict = "malicious"
            overall_conf = max(0.8, max_conf) if malicious_votes >= 2 else max(0.6, max_conf)
        elif total_valid > 0:
            overall_verdict = "clean"
            overall_conf = 0.1
        else:
            overall_verdict = "unknown"
            overall_conf = 0.0

        return {
            "ioc": ioc,
            "ioc_type": ioc_type,
            "overall_verdict": overall_verdict,
            "overall_confidence": round(overall_conf, 2),
            "confirming_malicious_providers": malicious_votes,
            "tags": list(all_tags),
            "malware_families": list(malware_families),
            "threat_actors": list(threat_actors),
            "providers": provider_summaries,
            "enriched_at": datetime.utcnow().isoformat() + "Z"
        }

    def _persist_records(
        self, db: Session, ioc: str, ioc_type: str, provider_results: List[ProviderResult]
    ):
        try:
            for p_res in provider_results:
                rec = ThreatIntelRecord(
                    id=uuid.uuid4(),
                    ioc=ioc,
                    ioc_type=ioc_type,
                    provider=p_res.provider,
                    confidence=p_res.confidence,
                    reputation=p_res.reputation,
                    tags=",".join(p_res.tags) if p_res.tags else None,
                    malware_family=p_res.malware_family,
                    threat_actor=p_res.threat_actor,
                    source=p_res.source,
                    raw_response=p_res.raw_response,
                    cache_expiry=datetime.utcnow() + timedelta(seconds=self.cache_ttl),
                    created_at=datetime.utcnow()
                )
                db.add(rec)
            db.commit()
        except Exception as e:
            db.rollback()
            logger.error(f"Failed to persist ThreatIntelRecords: {e}")

    def _enrich_alert(
        self, db: Session, alert_id: str, malicious_count: int, max_confidence: float
    ) -> Tuple[bool, Optional[float]]:
        try:
            alert_uuid = uuid.UUID(alert_id)
            alert = db.query(Alert).filter(Alert.id == alert_uuid).first()
            if not alert:
                return False, None

            if malicious_count >= 1:
                # Elevate risk score if threat intelligence confirmed malicious indicators
                escalated_score = min(1.0, max(alert.risk_score, 0.90 + (0.05 * malicious_count)))
                old_score = alert.risk_score
                alert.risk_score = escalated_score

                # Audit log for alert escalation
                audit = AuditLog(
                    id=uuid.uuid4(),
                    action="ALERT_ENRICHED",
                    target_entity="alerts",
                    details=(
                        f"Threat intel enriched alert {alert_id}: "
                        f"{malicious_count} malicious IOCs detected. "
                        f"Escalated risk score from {old_score:.2f} to {escalated_score:.2f}."
                    )
                )
                db.add(audit)
                db.commit()
                logger.info(f"Alert {alert_id} risk score escalated to {escalated_score:.2f}")
                return True, escalated_score

            return False, alert.risk_score
        except Exception as e:
            db.rollback()
            logger.error(f"Failed to enrich alert {alert_id}: {e}")
            return False, None
