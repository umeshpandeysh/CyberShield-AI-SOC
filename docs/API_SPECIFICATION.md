# API Specification (OpenAPI-Ready)

This specification defines the REST API endpoints exposed by the **CyberShield-AI-SOC** Backend API service. All request and response bodies must adhere to these JSON schemas.

---

## 1. Authentication Endpoints

### 1.1 `POST /api/v1/auth/login`
Authenticates a user and returns a JWT access token.

* **Request Body** (`application/json`):
  ```json
  {
    "email": "analyst@cybershield.io",
    "password": "Password123!"
  }
  ```
* **Success Response** (`200 OK`):
  ```json
  {
    "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
    "token_type": "bearer",
    "role": "Analyst_L1",
    "expires_in": 3600
  }
  ```
* **Error Response** (`401 Unauthorized`):
  ```json
  {
    "detail": "Invalid credentials or inactive account."
  }
  ```

---

## 2. Ingestion Endpoints

### 2.1 `POST /api/v1/ingest/email`
Uploads a raw email file (RFC822 `.eml`) to the threat processing queue.

* **Request Headers**:
  * `Authorization: Bearer <token>`
* **Request Body** (`multipart/form-data`):
  * `file`: (Binary attachment, `.eml` format)
* **Success Response** (`202 Accepted`):
  ```json
  {
    "email_id": "18f97ef9-813c-449e-8c34-7de20e176bfa",
    "message_id": "<202608012113.a9f82d0e@mail.attacker.com>",
    "status": "Queued",
    "received_at": "2026-08-01T21:13:55Z"
  }
  ```
* **Error Response** (`400 Bad Request`):
  ```json
  {
    "detail": "Invalid email structure or corrupted EML file."
  }
  ```

---

## 3. Alerts & Incident Management Endpoints

### 3.1 `GET /api/v1/alerts`
Retrieves a paginated list of generated threat alerts, filterable by threat level and case assignment.

* **Request Headers**:
  * `Authorization: Bearer <token>`
* **Query Parameters**:
  * `status`: (String - `OPEN`, `INVESTIGATING`, `RESOLVED_QUARANTINED`, `RESOLVED_FALSE_POSITIVE`)
  * `min_score`: (Float - filter risk score, range 0.0 - 1.0)
  * `limit`: (Integer - default 20)
  * `offset`: (Integer - default 0)
* **Success Response** (`200 OK`):
  ```json
  {
    "data": [
      {
        "id": "787c88b9-43c3-42be-bc55-a2283a00508a",
        "email_id": "18f97ef9-813c-449e-8c34-7de20e176bfa",
        "sender": "attacker@phish-domain.com",
        "subject": "URGENT: Verify Your Bank Details Now",
        "risk_score": 0.94,
        "status": "OPEN",
        "assigned_to": null,
        "created_at": "2026-08-01T21:14:02Z"
      }
    ],
    "pagination": {
      "total": 142,
      "limit": 20,
      "offset": 0
    }
  }
  ```

### 3.2 `GET /api/v1/alerts/{id}`
Returns the comprehensive threat inspection logs and analytical breakdown for a specific alert.

* **Request Headers**:
  * `Authorization: Bearer <token>`
* **Success Response** (`200 OK`):
  ```json
  {
    "id": "787c88b9-43c3-42be-bc55-a2283a00508a",
    "risk_score": 0.94,
    "status": "OPEN",
    "assigned_to": null,
    "email": {
      "id": "18f97ef9-813c-449e-8c34-7de20e176bfa",
      "message_id": "<202608012113.a9f82d0e@mail.attacker.com>",
      "sender": "attacker@phish-domain.com",
      "recipient": "employee@mycompany.com",
      "subject": "URGENT: Verify Your Bank Details Now",
      "body_text": "Please verify your credentials at http://fakebank-login.com...",
      "received_at": "2026-08-01T21:13:55Z"
    },
    "ai_analysis": {
      "phishing_probability": 0.965,
      "spam_probability": 0.082,
      "critical_tokens": ["URGENT", "verify", "bank details", "fakebank-login"]
    },
    "yara_matches": [
      {
        "rule_name": "Phishing_Bank_Social_Engineering",
        "tags": "phish, banking",
        "matched_strings": ["verify", "bank details"]
      }
    ],
    "attachments": [
      {
        "id": "efb8c9d0-c3d4-4a5b-6c7d-8e9f01234567",
        "filename": "invoice_pdf.exe",
        "file_size": 245800,
        "file_hash_sha256": "8f3c3a9f82d0e91b0d528bfa6c7200934f3a5be87538a6f393e4775496476937",
        "virus_found": true,
        "threat_label": "Win.Trojan.Agent-1944"
      }
    ],
    "urls": [
      {
        "url": "http://fakebank-login.com/secure",
        "vt_positives": 18,
        "vt_total": 75,
        "status": "Malicious"
      }
    ]
  }
  ```

### 3.3 `PATCH /api/v1/alerts/{id}/triage`
Updates the workflow status and logs analyst decisions.

* **Request Headers**:
  * `Authorization: Bearer <token>`
* **Request Body** (`application/json`):
  ```json
  {
    "status": "RESOLVED_QUARANTINED",
    "assigned_to": "887a88b9-43c3-42be-bc55-a2283a00508a",
    "comments": "Confirmed bank phishing impersonation with executable attachment payload."
  }
  ```
* **Success Response** (`200 OK`):
  ```json
  {
    "alert_id": "787c88b9-43c3-42be-bc55-a2283a00508a",
    "status": "RESOLVED_QUARANTINED",
    "updated_at": "2026-08-01T21:44:02Z",
    "triage_by": "887a88b9-43c3-42be-bc55-a2283a00508a"
  }
  ```

---

## 4. Threat Metrics Endpoints

### 4.1 `GET /api/v1/metrics/summary`
Retrieves daily security center statistics for dashboard graphs.

* **Request Headers**:
  * `Authorization: Bearer <token>`
* **Success Response** (`200 OK`):
  ```json
  {
    "statistics": {
      "total_processed_today": 1204,
      "unresolved_alerts_count": 14,
      "quarantined_today": 32,
      "false_positives_today": 5
    },
    "threat_distribution": {
      "phishing": 28,
      "spam": 145,
      "malware": 8
    }
  }
  ```
