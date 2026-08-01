import os
import sys
import importlib.util
import pytest
from fastapi.testclient import TestClient

# Load the ai-engine/main.py module dynamically to bypass the hyphen constraint in folder name
ai_engine_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../ai-engine/main.py"))
spec = importlib.util.spec_from_file_location("ai_engine_main", ai_engine_path)
ai_engine_main = importlib.util.module_from_spec(spec)
sys.modules["ai_engine_main"] = ai_engine_main
spec.loader.exec_module(ai_engine_main)

app = ai_engine_main.app
client = TestClient(app)

def test_ai_health_check():
    response = client.get("/api/v1/health")
    assert response.status_code == 200
    assert response.json()["status"] == "healthy"
    assert response.json()["service"] == "ai-engine"

def test_ai_classify_phishing():
    response = client.post(
        "/api/v1/classify",
        json={"email_id": "test_id_123", "body": "verify your account details immediately, urgent secure link action required"}
    )
    assert response.status_code == 200
    data = response.json()
    assert data["is_phishing"] is True
    assert data["phishing_probability"] >= 0.5
    assert len(data["explanations"]) > 0

def test_ai_classify_clean():
    response = client.post(
        "/api/v1/classify",
        json={"email_id": "test_id_456", "body": "hello team, can you review the draft design specs for the auth route"}
    )
    assert response.status_code == 200
    data = response.json()
    assert data["is_phishing"] is False
    assert data["phishing_probability"] < 0.5
