# Security Architecture Document

This document outlines the security controls, authentication mechanisms, authorization levels, and cryptography schemes implemented to protect the **CyberShield-AI-SOC** platform. It aligns with the **OWASP ASVS (Application Security Verification Standard) Level 2** and mitigates risks from the **OWASP Top 10**.

---

## 1. Authentication & Session Management (ASVS V2 / V3)

* **Protocol**: OAuth2 with JWT (JSON Web Tokens) for stateless HTTP requests.
* **Token Specifications**:
  * **Algorithm**: HMAC SHA-256 (`HS256`).
  * **Claims**:
    * `sub`: User database ID.
    * `role`: RBAC security role.
    * `jti`: Unique token identifier (used for token revocation).
    * `exp`: Token expiry timestamp (enforced at 60 minutes max).
* **Token Revocation**: Since JWTs are stateless, token revocation is managed by maintaining a **Redis blacklist** of `jti` hashes. During logout or password reset, the token is written to Redis with a TTL matching the token's remaining lifespan.

---

## 2. Role-Based Access Control (RBAC - ASVS V4)

Permissions are strictly mapped to security roles:

| Role | Permissions | Description |
| ---- | ----------- | ----------- |
| **Admin** | `*` (All permissions) | Can create users, update YARA rulesets, alter system thresholds, view full audit logs. |
| **Analyst_L2** | `view_alerts`, `triage_alerts`, `quarantine_sender`, `suppress_alert` | Can perform full case investigations, suppress indicators, and block IPs/Domains. |
| **Analyst_L1** | `view_alerts`, `triage_alerts` | Can inspect indicators and transition case states between `OPEN` and `INVESTIGATING`. |

---

## 3. Cryptography & Data Protection (ASVS V6)

### 3.1 Encryption in Transit
* **Protocols**: All communication routes (web, API, Celery task streams, database connection strings) must require **TLS 1.3**.
* **Ciphers**: Restricted to modern cipher suites:
  * `TLS_AES_256_GCM_SHA384`
  * `TLS_CHACHA20_POLY1305_SHA256`

### 3.2 Encryption at Rest
* **Database Columns**: Highly sensitive values (e.g., mail configurations, external integration API keys) are encrypted before insertion into PostgreSQL using **AES-256-GCM**.
* **Key Derivation**: Keys are derived from master system passwords using **PBKDF2** with 600,000 iterations and random salts.
* **Attachment Files**: Extracted email attachments are quarantined on disk under `/data/quarantine` with restricted system permissions (`chmod 600`).

---

## 4. API Rate Limiting (OWASP Top 10: API4:2023 Lack of Resources)

To prevent brute force, enumeration, and Denial of Service (DoS) attacks:
* **Algorithm**: Token Bucket algorithm.
* **Store**: Managed dynamically in Redis to ensure synchronized limits across backend replicas.
* **Defaults**:
  * Public Auth Routes: `5 requests per minute` per IP address.
  * Ingestion API: `60 requests per minute` per authorized source client IP.
  * Standard Dashboard APIs: `200 requests per minute` per authenticated session.

---

## 5. Security Auditing & Logs (ASVS V8)

The system maintains an **immutable audit log** (`audit_logs` table) alongside traditional system logging:

* **Log Contents**: User actions (`login`, `quarantine`, `suppress`, `user_update`) are logged with the executing IP address, userID, target entity, timestamp, and a JSON diff of the changed attributes.
* **Integrity**: To ensure the log's integrity, write privileges to the `audit_logs` table are restricted. No update or delete operations are permitted on this table via application routes.
* **Log Aggregation**: Application logs must write in structured JSON layout to `stdout` for ingestion by collectors (Logstash/Fluentbit) and forwarders. Sensitive values (passwords, JWT strings, email PII) must be masked automatically.
