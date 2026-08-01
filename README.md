# CyberShield-AI-SOC 🛡️🤖

[![CI Pipeline](https://github.com/umeshpandeysh/CyberShield-AI-SOC/actions/workflows/ci.yml/badge.svg)](https://github.com/umeshpandeysh/CyberShield-AI-SOC/actions)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python Version](https://img.shields.io/badge/python-3.10%20%7C%203.11-blue.svg)](https://www.python.org/)
[![Node Version](https://img.shields.io/badge/node-%3E%3D18.0.0-green.svg)](https://nodejs.org/)

**CyberShield-AI-SOC** is a production-grade, AI-powered Security Operations Center (SOC) platform designed for email threat detection, automated threat hunting, and security incident response. It integrates state-of-the-art Natural Language Processing (NLP) models, traditional signature scans, and custom heuristic rule engines to identify phishing, spam, malware attachments, and malicious payloads.

## 🚀 Key Features

* **Real-time Ingestion & Parsing**: High-performance email ingestion supporting SMTP listener and API-based integrations.
* **Hybrid Threat Analysis Engine**:
  * **AI/ML Classifiers**: Transformers-based NLP engine classifying email bodies and headers for spear-phishing and spam.
  * **YARA Rule Parser**: Custom and community YARA rules targeting phishing kit indicators, malicious headers, and suspicious payloads.
  * **ClamAV Anti-Malware**: Real-time attachment file scanning for trojans, worms, and viruses.
  * **VirusTotal Lookup**: IP, domain, URL, and file hash threat intelligence enrichment.
* **SOC Analyst Dashboard**:
  * Rich React interface providing incident queues, threat maps, and telemetry graphs.
  * Interactive incident timeline and sandbox investigation tools.
* **Multi-Container Architecture**: Dockerized services orchestrated by Docker Compose for easy scaling and testing.

## 🛠️ Technology Stack

* **Frontend**: React, TypeScript, TailwindCSS (for responsive UI/UX), Lucide React (for icons)
* **Backend**: FastAPI (Python), PostgreSQL (Database), Redis (Task Queue & Cache)
* **AI Engine**: PyTorch, Transformers (Hugging Face), Scikit-Learn
* **Threat Services**: YARA (signature matching), ClamAV daemon, VirusTotal API
* **Deployment & Ops**: Docker, Docker-Compose, GitHub Actions (CI/CD)

---

## 📂 Directory Structure

```text
CyberShield-AI-SOC/
├── frontend/              # React/TypeScript Analyst Dashboard UI
├── backend/               # FastAPI REST API & Ingestion Pipeline
├── ai-engine/             # Machine learning classifiers (PyTorch/Transformers)
├── services/              # Threat-Intel APIs, ClamAV, and YARA integrations
├── datasets/              # Sample training/testing datasets (e.g. spam/phishing)
├── models/                # Saved weights and serialized AI models
├── yara-rules/            # Custom and community YARA signatures
├── docker/                # Custom Dockerfiles and build scripts
├── docs/                  # Architecture, setup guides, and API docs
├── scripts/               # Training, database seeds, and utility scripts
├── tests/                 # Unit, integration, and E2E test suites
├── reports/               # Auto-generated incident reports and PDF logs
├── .github/               # GitHub Actions CI workflows and Issue/PR templates
├── README.md              # Project onboarding guide
├── LICENSE                # MIT License
├── SECURITY.md            # Security reporting policies
├── CONTRIBUTING.md        # Code guidelines and workflows
├── CHANGELOG.md           # Version release tracking
├── CODE_OF_CONDUCT.md     # Contributor community guidelines
├── .gitignore             # Ignored files for Python/Node/OS/Docker/IDEs
├── .env.example           # Example local development variables
└── docker-compose.yml     # Local multi-service orchestration
```

---

## 🚦 Getting Started

### Prerequisites

Ensure you have the following installed on your machine:
* Python `3.10+` or `3.11+`
* Node.js `18.0.0+` & npm
* Docker & Docker Compose
* Git

### Installation & Local Setup

1. **Clone the repository**:
   ```bash
   git clone https://github.com/umeshpandeysh/CyberShield-AI-SOC.git
   cd CyberShield-AI-SOC
   ```

2. **Configure Environment Variables**:
   Copy the example environment file and configure variables:
   ```bash
   cp .env.example .env
   ```
   *(Ensure to configure databases, external service API tokens, and JWT secrets in your `.env`)*

3. **Spin Up Infrastructural Services**:
   Use docker-compose to start PostgreSQL, Redis, and ClamAV:
   ```bash
   docker-compose up -d db redis clamav
   ```

4. **Initialize and Run Backend**:
   ```bash
   cd backend
   python -m venv venv
   source venv/bin/activate  # On Windows: .\venv\Scripts\activate
   pip install -r requirements.txt
   uvicorn app.main:app --reload
   ```

5. **Initialize and Run Frontend**:
   ```bash
   cd ../frontend
   npm install
   npm run dev
   ```

---

## 🔒 Security

For security vulnerability reporting, please see [SECURITY.md](file:///C:/Users/UMESH%20PANDEY/Downloads/ceenew/CyberShield-AI-SOC/SECURITY.md).

## 📄 License

This project is licensed under the MIT License. See [LICENSE](file:///C:/Users/UMESH%20PANDEY/Downloads/ceenew/CyberShield-AI-SOC/LICENSE) for details.
