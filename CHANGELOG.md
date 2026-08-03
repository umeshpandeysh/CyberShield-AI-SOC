# Changelog

All notable changes to **CyberShield-AI-SOC** will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2026-08-03

### Added
- **MIME Email Ingestion & Parser Engine**:
  - RFC822 `.eml` parser extracting headers, HTML/plain text body, extracted URLs, and attachment binaries.
  - Asynchronous background ingestion (`POST /api/v1/ingest/email/async`) returning `202 Accepted` with tracking ID.
  - RFC822 `Message-ID` deduplication.

- **IOC Extraction & Normalization**:
  - Regex classifier and validator for URLs, domains, IPv4, IPv6, email addresses, MD5, SHA1, and SHA256 hashes.
  - Database schema persisting extracted indicators across `url_indicators`, `attachments`, and `yara_matches`.

- **Threat Scanning Engine**:
  - **ClamAV** daemon integration for attachment malware scanning.
  - **YARA** engine integration running custom rule signatures against headers and bodies.
  - Failure resilience and graceful fallback execution.

- **AI Threat Classification Engine**:
  - **DistilBERT** NLP transformer model for phishing detection.
  - **XGBoost** metadata classification model for structural anomaly scoring.
  - Hybrid risk score aggregation ($R = 0.6 \cdot P_{\text{text}} + 0.4 \cdot P_{\text{meta}}$).
  - Explainable AI (XAI) token extraction explaining threat classification rationale.

- **Asynchronous Processing Pipeline**:
  - **Celery + Redis** task distribution queue.
  - Exponential backoff retries (max 3 retries, 30s backoff multiplier).
  - Dead-letter failure handling and task monitoring endpoints (`GET /api/v1/tasks`).

- **SOC Case Management & Alert Triage**:
  - Incident investigation lifecycle tracking (`Open`, `Investigating`, `Containment`, `Eradication`, `Recovery`, `Closed`).
  - Case notes (`CaseNote`), evidence tracking (`CaseEvidence`), and chronological activity timeline (`CaseEvent`).
  - Immutable audit trail logging (`AuditLog`).
  - Role-Based Access Control (RBAC) supporting `Admin`, `Analyst_L1`, and `Analyst_L2`.

- **Threat Intelligence & IOC Enrichment**:
  - Pluggable provider abstraction for **VirusTotal**, **AbuseIPDB**, **URLHaus**, **AlienVault OTX**, and **OpenPhish**.
  - `CircuitBreaker` pattern (`CLOSED`, `OPEN`, `HALF_OPEN`), timeout handling, and retry policies.
  - Redis/in-memory caching with configurable TTL (`THREAT_INTEL_CACHE_TTL`).
  - Automatic alert risk score escalation upon multi-provider malicious consensus.
  - Endpoints for single/batch IOC enrichment, provider health monitoring, and cache management.

- **Real-Time Telemetry & WebSockets**:
  - `WebSocket /ws/notifications` live streaming endpoint for real-time alert notifications and task updates.

- **Threat Metrics, Analytics & Reporting**:
  - Summary metrics (`GET /api/v1/metrics/summary`) and 7-day trend analytics (`GET /api/v1/metrics/analytics`).
  - Executive report export in JSON, plain text, and PDF format (`GET /api/v1/reports/case/{id}`).

- **User Administration & Settings**:
  - User creation, active status control, role management, and audit log search (`/api/v1/admin`).
  - Detection confidence threshold and cache TTL settings configuration (`/api/v1/settings`).

- **React SOC Dashboard Frontend**:
  - High-contrast glassmorphic dark mode UI built with React 18, Vite, and TypeScript.
  - Dashboard Overview, Alert Triage Queue, Incident Cases Drawer, Threat Intel Explorer, Live Tasks Stream, Analytics, and Admin/Settings.

- **DevOps & Infrastructure Stack**:
  - Production `docker-compose.prod.yml` and `Dockerfile`.
  - Kubernetes manifests (`deploy/k8s/`) and Helm chart (`deploy/helm/`).
  - Prometheus metrics configuration (`deploy/monitoring/prometheus.yml`).
  - PostgreSQL backup and restore automation script (`scripts/backup_restore.sh`).
  - Sample RFC822 `.eml` files for testing (`samples/phishing_sample.eml`, `samples/benign_sample.eml`).
