# Product Requirements Document (PRD)

## 1. Executive Summary & Vision

### 1.1 Vision Statement
To establish an intelligent, highly-scalable, and automated Email Threat Detection and Security Operations Center (SOC) platform. **CyberShield-AI-SOC** acts as an enterprise-grade line of defense that ingests, parses, analyzes, and mitigates email-based security threats (phishing, spam, business email compromise, malware attachments) by blending machine learning classifiers, YARA heuristics, and static multi-engine file scans.

### 1.2 Objectives
* **Automate Triage**: Decrease the Mean Time to Detect (MTTD) and Mean Time to Respond (MTTR) for email threats from hours to seconds.
* **Intelligent Defense**: Provide accurate NLP-based classification of email text, preventing spear-phishing that bypasses standard signature filters.
* **Unified Investigations**: Offer SOC analysts a comprehensive workbench that displays complete indicators of compromise (IoCs), headers, body text, YARA hits, and sandbox results in one unified view.

---

## 2. Target Personas

### 2.1 Tier 1/2 SOC Analyst (Primary User)
* **Goal**: Investigate flagged emails quickly, determine if they are malicious, and either quarantine them or mark them as false positives.
* **Pain Point**: Alert fatigue from high volumes of spam/phishing false positives, context-switching between different threat intel portals.

### 2.2 Security Administrator / Architect
* **Goal**: Configure threat detection thresholds, update YARA rules, review false positive rates, manage integrations, and ensure system uptime.
* **Pain Point**: Rigid systems that cannot easily integrate custom heuristics, lack of auditable logs for compliance.

---

## 3. Functional Requirements

### 3.1 Email Ingestion Pipeline
* **REQ-ING-001**: Support ingestion via a high-throughput REST API endpoint (`/api/v1/ingest`).
* **REQ-ING-002**: Poll IMAP/POP3 enterprise mailboxes on a configurable cron schedule.
* **REQ-ING-003**: Parse raw email files (RFC 822 / `.eml` format) extracting:
  * Headers (SPF, DKIM, DMARC, Received chain, Sender IP).
  * Email Body (Plain text and HTML).
  * Attachments (extract filenames, sizes, and binary payloads).
  * Hyperlinks (extract all URLs from HTML/Text).

### 3.2 Hybrid Threat Detection
* **REQ-DET-001**: Execute NLP text classification to determine phishing and spam probabilities.
* **REQ-DET-002**: Run customizable YARA rules over email body content and extracted headers to detect phishing kits, obfuscated scripts, and social engineering indicators.
* **REQ-DET-003**: Check all extracted URLs and file hashes against the VirusTotal API.
* **REQ-DET-004**: Stream email attachments directly to a local ClamAV daemon for signature-based malware scanning.

### 3.3 Incident Case Management & Dashboard
* **REQ-INC-001**: Real-time listing of security alerts sorted by risk score (High, Medium, Low).
* **REQ-INC-002**: Visual graphs showing telemetry data (daily threat counts, categorization ratios, top target domains).
* **REQ-INC-003**: Case details page containing:
  * Raw header inspector.
  * Extracted URL and attachment lists with threat status.
  * AI explanation scores.
  * Audit log of actions taken.
* **REQ-INC-004**: Execution of analyst containment actions:
  * "Quarantine Sender" (Blocklist IP/Domain).
  * "Suppress Alert" (Add sender to Safelist).
  * "Trigger Remediation" (Webhook integration to delete email from mailboxes).

---

## 4. Non-Functional Requirements (NFRs)

### 4.1 Performance & Scalability
* **NFR-PER-001**: Ingestion to classification latency must be under **3 seconds** for emails up to 10MB (excluding external API timeout delays).
* **NFR-PER-002**: Support horizontal scaling of backend workers to handle up to **100 emails per second**.
* **NFR-PER-003**: API response times for dashboard data must be under **500ms** (95th percentile).

### 4.2 Security & Compliance
* **NFR-SEC-001**: All data in transit must utilize **TLS 1.3**.
* **NFR-SEC-002**: Sensitive fields in the database (API tokens, user credentials) must be encrypted at rest using **AES-GCM-256**.
* **NFR-SEC-003**: The application must comply with **OWASP ASVS (Application Security Verification Standard) Level 2**.
* **NFR-SEC-004**: Compliance with GDPR and CCPA concerning personal information storage (masking PII in audit trails).

### 4.3 Reliability & Availability
* **NFR-REL-001**: Ensure **99.9%** availability of the primary web dashboard.
* **NFR-REL-002**: Failures of third-party APIs (e.g., VirusTotal lookup) must not block core email analysis; instead, the system must degrade gracefully and queue retries.

---

## 5. Success Metrics & KPIs

| Metric | Target | Measurement Method |
| ------ | ------ | ------------------ |
| **Mean Time to Detect (MTTD)** | < 5 seconds | Ingestion timestamp to database write timestamp |
| **Mean Time to Respond (MTTR)** | < 2 minutes | Alert generation to analyst trigger remediation |
| **AI Classification F1-Score** | > 95% | Calculated weekly using analyst validated label feedbacks |
| **API Availability** | > 99.9% | Synthetic monitoring and uptime checks |
| **False Positive Rate** | < 2% | Calculated using feedback logs of false alerts |
