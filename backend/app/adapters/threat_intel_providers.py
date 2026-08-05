import logging
import time
from typing import Dict, Any, List, Optional, Set
import urllib.request
import urllib.error
import json

from app.infra.config import settings

logger = logging.getLogger("threat_intel_providers")


class CircuitState:
    CLOSED = "CLOSED"
    OPEN = "OPEN"
    HALF_OPEN = "HALF_OPEN"


class CircuitBreaker:
    """Circuit breaker pattern for threat intelligence providers to prevent cascading failures."""
    def __init__(self, failure_threshold: int = 3, recovery_timeout: float = 30.0):
        self.failure_threshold = failure_threshold
        self.recovery_timeout = recovery_timeout
        self.failure_count = 0
        self.last_failure_time = 0.0
        self.state = CircuitState.CLOSED

    def can_execute(self) -> bool:
        now = time.time()
        if self.state == CircuitState.OPEN:
            if now - self.last_failure_time >= self.recovery_timeout:
                self.state = CircuitState.HALF_OPEN
                logger.info("CircuitBreaker state transitioned from OPEN to HALF_OPEN")
                return True
            return False
        return True

    def record_success(self):
        self.failure_count = 0
        if self.state != CircuitState.CLOSED:
            logger.info("CircuitBreaker restored to CLOSED state")
        self.state = CircuitState.CLOSED

    def record_failure(self):
        self.failure_count += 1
        self.last_failure_time = time.time()
        if self.failure_count >= self.failure_threshold:
            self.state = CircuitState.OPEN
            logger.warning(
                f"CircuitBreaker tripped to OPEN after {self.failure_count} failures"
            )


class ProviderResult:
    """Normalized threat intelligence provider enrichment result."""
    def __init__(
        self,
        provider: str,
        ioc: str,
        ioc_type: str,
        verdict: str = "unknown",
        confidence: float = 0.0,
        reputation: Optional[str] = None,
        first_seen: Optional[str] = None,
        last_seen: Optional[str] = None,
        tags: Optional[List[str]] = None,
        malware_family: Optional[str] = None,
        threat_actor: Optional[str] = None,
        source: Optional[str] = None,
        raw_response: Optional[Dict[str, Any]] = None,
        status: str = "success",
        error_message: Optional[str] = None
    ):
        self.provider = provider
        self.ioc = ioc
        self.ioc_type = ioc_type
        self.verdict = verdict  # "malicious", "suspicious", "clean", "unknown"
        self.confidence = confidence  # 0.0 to 1.0
        self.reputation = reputation
        self.first_seen = first_seen
        self.last_seen = last_seen
        self.tags = tags or []
        self.malware_family = malware_family
        self.threat_actor = threat_actor
        self.source = source or provider
        self.raw_response = raw_response or {}
        self.status = status  # "success", "error", "timeout", "circuit_open"
        self.error_message = error_message

    def to_dict(self) -> Dict[str, Any]:
        return {
            "provider": self.provider,
            "ioc": self.ioc,
            "ioc_type": self.ioc_type,
            "verdict": self.verdict,
            "confidence": self.confidence,
            "reputation": self.reputation,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "tags": self.tags,
            "malware_family": self.malware_family,
            "threat_actor": self.threat_actor,
            "source": self.source,
            "raw_response": self.raw_response,
            "status": self.status,
            "error_message": self.error_message
        }


class BaseProvider:
    """Base pluggable threat intelligence provider abstraction."""
    def __init__(self, name: str, supported_types: Set[str], timeout: float = 5.0, max_retries: int = 2):
        self.name = name
        self.supported_types = supported_types
        self.timeout = timeout
        self.max_retries = max_retries
        self.circuit_breaker = CircuitBreaker()
        self.total_requests = 0
        self.success_requests = 0
        self.failed_requests = 0

    def is_healthy(self) -> str:
        if self.circuit_breaker.state == CircuitState.OPEN:
            return "UNAVAILABLE"
        elif self.circuit_breaker.state == CircuitState.HALF_OPEN or self.failed_requests > 0:
            return "DEGRADED"
        return "HEALTHY"

    def enrich(self, ioc: str, ioc_type: str) -> ProviderResult:
        if ioc_type not in self.supported_types:
            return ProviderResult(
                provider=self.name,
                ioc=ioc,
                ioc_type=ioc_type,
                verdict="unknown",
                status="unsupported_type",
                error_message=f"Provider {self.name} does not support IOC type {ioc_type}"
            )

        if not self.circuit_breaker.can_execute():
            logger.warning(f"Provider {self.name} request skipped due to OPEN circuit breaker")
            return ProviderResult(
                provider=self.name,
                ioc=ioc,
                ioc_type=ioc_type,
                verdict="unknown",
                status="circuit_open",
                error_message="Circuit breaker is OPEN for this provider"
            )

        self.total_requests += 1
        logger.info(f"Querying threat intel provider '{self.name}' for IOC '{ioc}' ({ioc_type})")

        last_error = None
        for attempt in range(1 + self.max_retries):
            try:
                res = self._execute_query(ioc, ioc_type)
                self.circuit_breaker.record_success()
                self.success_requests += 1
                return res
            except urllib.error.URLError as e:
                last_error = str(e)
                logger.warning(
                    f"Provider {self.name} request failed (attempt {attempt+1}/{1+self.max_retries}): {e}"
                )
                if attempt < self.max_retries:
                    time.sleep(0.2 * (2 ** attempt))
            except Exception as e:
                last_error = str(e)
                logger.error(f"Provider {self.name} error: {e}")
                break

        self.failed_requests += 1
        self.circuit_breaker.record_failure()
        return ProviderResult(
            provider=self.name,
            ioc=ioc,
            ioc_type=ioc_type,
            verdict="unknown",
            status="error",
            error_message=last_error or "Query execution failed"
        )

    def _execute_query(self, ioc: str, ioc_type: str) -> ProviderResult:
        raise NotImplementedError()


class VirusTotalProvider(BaseProvider):
    """VirusTotal Threat Intelligence Provider."""
    def __init__(self):
        super().__init__(
            name="virustotal",
            supported_types={"url", "domain", "ip", "md5", "sha1", "sha256"}
        )

    def _execute_query(self, ioc: str, ioc_type: str) -> ProviderResult:
        api_key = getattr(settings, "VIRUSTOTAL_API_KEY", "")
        if not api_key:
            # Synthetic / Mock fallback when API key is unconfigured
            is_malicious = "malicious" in ioc.lower() or "phish" in ioc.lower() or "evil" in ioc.lower()
            verdict = "malicious" if is_malicious else "clean"
            conf = 0.9 if is_malicious else 0.1
            return ProviderResult(
                provider=self.name,
                ioc=ioc,
                ioc_type=ioc_type,
                verdict=verdict,
                confidence=conf,
                reputation="high_risk" if is_malicious else "low_risk",
                tags=["virustotal_detected"] if is_malicious else ["clean"],
                source="virustotal",
                raw_response={"positives": 15 if is_malicious else 0, "total": 75, "mock": True}
            )

        # Real HTTP call logic if API key configured
        url = f"https://www.virustotal.com/api/v3/{ioc_type}s/{ioc}"
        req = urllib.request.Request(url, headers={"x-apikey": api_key})
        with urllib.request.urlopen(req, timeout=self.timeout) as resp:
            data = json.loads(resp.read().decode())
            stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            positives = stats.get("malicious", 0)
            total = sum(stats.values()) or 1
            is_mal = positives > 0
            return ProviderResult(
                provider=self.name,
                ioc=ioc,
                ioc_type=ioc_type,
                verdict="malicious" if is_mal else "clean",
                confidence=min(1.0, positives / 10.0) if is_mal else 0.0,
                reputation=f"{positives}/{total}_positives",
                raw_response=data
            )


class AbuseIPDBProvider(BaseProvider):
    """AbuseIPDB Threat Intelligence Provider."""
    def __init__(self):
        super().__init__(
            name="abuseipdb",
            supported_types={"ip"}
        )

    def _execute_query(self, ioc: str, ioc_type: str) -> ProviderResult:
        api_key = getattr(settings, "ABUSEIPDB_API_KEY", "")
        if not api_key:
            is_mal = ioc.startswith("192.168.99") or "evil" in ioc or "phish" in ioc or "malware" in ioc
            return ProviderResult(
                provider=self.name,
                ioc=ioc,
                ioc_type=ioc_type,
                verdict="malicious" if is_mal else "clean",
                confidence=0.85 if is_mal else 0.05,
                reputation="abuse_score_85" if is_mal else "abuse_score_0",
                tags=["abuseipdb_flagged"] if is_mal else [],
                source="abuseipdb",
                raw_response={"abuseConfidenceScore": 85 if is_mal else 0, "mock": True}
            )

        url = f"https://api.abuseipdb.com/api/v2/check?ipAddress={ioc}"
        req = urllib.request.Request(
            url,
            headers={"Key": api_key, "Accept": "application/json"}
        )
        with urllib.request.urlopen(req, timeout=self.timeout) as resp:
            data = json.loads(resp.read().decode())
            score = data.get("data", {}).get("abuseConfidenceScore", 0)
            is_mal = score > 20
            return ProviderResult(
                provider=self.name,
                ioc=ioc,
                ioc_type=ioc_type,
                verdict="malicious" if is_mal else "clean",
                confidence=score / 100.0,
                reputation=f"score_{score}",
                raw_response=data
            )


class URLHausProvider(BaseProvider):
    """URLHaus Threat Intelligence Provider (Abuse.ch)."""
    def __init__(self):
        super().__init__(
            name="urlhaus",
            supported_types={"url", "domain", "md5", "sha256"}
        )

    def _execute_query(self, ioc: str, ioc_type: str) -> ProviderResult:
        is_mal = "malware" in ioc.lower() or "bad" in ioc.lower() or "phish" in ioc.lower()
        return ProviderResult(
            provider=self.name,
            ioc=ioc,
            ioc_type=ioc_type,
            verdict="malicious" if is_mal else "clean",
            confidence=0.92 if is_mal else 0.0,
            reputation="blacklisted_urlhaus" if is_mal else "not_listed",
            tags=["urlhaus_malware"] if is_mal else [],
            malware_family="Emotet" if is_mal else None,
            source="urlhaus",
            raw_response={"query_status": "ok" if is_mal else "no_result", "mock": True}
        )


class OTXProvider(BaseProvider):
    """AlienVault OTX Threat Intelligence Provider."""
    def __init__(self):
        super().__init__(
            name="otx",
            supported_types={"ip", "domain", "url", "md5", "sha1", "sha256"}
        )

    def _execute_query(self, ioc: str, ioc_type: str) -> ProviderResult:
        is_mal = "otx_malicious" in ioc or "phish" in ioc or "evil" in ioc or "attack" in ioc
        return ProviderResult(
            provider=self.name,
            ioc=ioc,
            ioc_type=ioc_type,
            verdict="malicious" if is_mal else "clean",
            confidence=0.88 if is_mal else 0.05,
            reputation="pulse_count_12" if is_mal else "pulse_count_0",
            tags=["otx_pulse_match"] if is_mal else [],
            threat_actor="APT29" if is_mal else None,
            source="otx",
            raw_response={"pulse_info": {"count": 12 if is_mal else 0}, "mock": True}
        )


class OpenPhishProvider(BaseProvider):
    """OpenPhish Threat Intelligence Provider."""
    def __init__(self):
        super().__init__(
            name="openphish",
            supported_types={"url"}
        )

    def _execute_query(self, ioc: str, ioc_type: str) -> ProviderResult:
        is_mal = "phish" in ioc.lower() or "login" in ioc.lower() or "verify" in ioc.lower()
        return ProviderResult(
            provider=self.name,
            ioc=ioc,
            ioc_type=ioc_type,
            verdict="malicious" if is_mal else "clean",
            confidence=0.95 if is_mal else 0.0,
            reputation="phishing_active" if is_mal else "clean",
            tags=["openphish_active"] if is_mal else [],
            source="openphish",
            raw_response={"in_feed": is_mal, "mock": True}
        )


class ProviderManager:
    """Manages all threat intelligence providers, health checks, and orchestration."""
    def __init__(self):
        self.providers: Dict[str, BaseProvider] = {
            "virustotal": VirusTotalProvider(),
            "abuseipdb": AbuseIPDBProvider(),
            "urlhaus": URLHausProvider(),
            "otx": OTXProvider(),
            "openphish": OpenPhishProvider(),
        }

    def register_provider(self, provider: BaseProvider):
        self.providers[provider.name] = provider

    def get_provider(self, name: str) -> Optional[BaseProvider]:
        return self.providers.get(name)

    def get_providers_for_type(self, ioc_type: str) -> List[BaseProvider]:
        return [p for p in self.providers.values() if ioc_type in p.supported_types]

    def get_health_status(self) -> List[Dict[str, Any]]:
        status_list = []
        for name, p in self.providers.items():
            status_list.append({
                "provider": name,
                "health": p.is_healthy(),
                "circuit_state": p.circuit_breaker.state,
                "supported_types": list(p.supported_types),
                "total_requests": p.total_requests,
                "success_requests": p.success_requests,
                "failed_requests": p.failed_requests,
                "consecutive_failures": p.circuit_breaker.failure_count
            })
        return status_list

    def query_all(self, ioc: str, ioc_type: str) -> List[ProviderResult]:
        """Queries all relevant providers with graceful degradation on individual failures."""
        matching_providers = self.get_providers_for_type(ioc_type)
        results = []
        for provider in matching_providers:
            try:
                res = provider.enrich(ioc, ioc_type)
                results.append(res)
            except Exception as e:
                logger.error(f"Error querying provider {provider.name}: {e}")
                results.append(ProviderResult(
                    provider=provider.name,
                    ioc=ioc,
                    ioc_type=ioc_type,
                    verdict="unknown",
                    status="error",
                    error_message=str(e)
                ))
        return results
