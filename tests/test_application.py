import pytest
import io
import json
from app import app
from database.database import init_db

@pytest.fixture
def client():
    app.config["TESTING"] = True
    app.config["WTF_CSRF_ENABLED"] = False
    init_db()
    with app.test_client() as client:
        yield client

def test_route_index(client):
    response = client.get("/")
    assert response.status_code == 200
    assert b"BAITDETECT" in response.data

def test_route_analyze_page(client):
    response = client.get("/analyze")
    assert response.status_code == 200
    assert b"Email Ingestion & Security Analysis" in response.data

def test_route_headers(client):
    response = client.get("/headers")
    assert response.status_code == 200

def test_route_urls(client):
    response = client.get("/urls")
    assert response.status_code == 200

def test_route_attachments(client):
    response = client.get("/attachments")
    assert response.status_code == 200

def test_route_indicators(client):
    response = client.get("/indicators")
    assert response.status_code == 200

def test_route_risk_assessment(client):
    response = client.get("/risk-assessment")
    assert response.status_code == 200

def test_route_history(client):
    response = client.get("/history")
    assert response.status_code == 200

def test_route_reports(client):
    response = client.get("/reports")
    assert response.status_code == 200

def test_route_settings(client):
    response = client.get("/settings")
    assert response.status_code == 200

def test_api_health(client):
    response = client.get("/api/v1/health")
    assert response.status_code == 200
    data = response.get_json()
    assert data["status"] == "operational"

def test_api_analyze_json(client):
    sample = {
        "raw_content": """From: "Bank Support" <alert@evil-bank.xyz>
To: victim@company.com
Subject: Account Alert: Immediate action required
Date: Tue, 24 Nov 2026 12:00:00 +0000
Message-ID: <msg991@evil-bank.xyz>

Your account will be suspended within 24 hours. Click here to verify:
http://198.51.100.99/login.php
"""
    }
    response = client.post("/api/v1/analyze", json=sample)
    assert response.status_code == 200
    data = response.get_json()
    assert data["success"]
    assert data["risk_score"] > 40
    assert "id" in data

    # Test PDF download for generated analysis
    analysis_id = data["id"]
    pdf_resp = client.get(f"/analysis/{analysis_id}/pdf")
    assert pdf_resp.status_code == 200
    assert pdf_resp.headers["Content-Type"] == "application/pdf"

    # Test JSON export endpoint
    json_resp = client.get(f"/analysis/{analysis_id}/json")
    assert json_resp.status_code == 200
    json_data = json_resp.get_json()
    assert json_data["id"] == analysis_id

def test_submit_analysis_file_upload(client):
    email_text = """From: news@service.com
Subject: Weekly Digest
Date: Tue, 24 Nov 2026 12:00:00 +0000
Message-ID: <digest01@service.com>

Here is your weekly news update.
"""
    data = {
        'email_file': (io.BytesIO(email_text.encode('utf-8')), 'test_sample.eml')
    }
    response = client.post('/analyze/submit', data=data, content_type='multipart/form-data', follow_redirects=True)
    assert response.status_code == 200
    assert b"Analysis completed successfully" in response.data

def test_security_file_extension_restriction(client):
    bad_data = {
        'email_file': (io.BytesIO(b"malicious payload"), 'exploit.exe')
    }
    response = client.post('/analyze/submit', data=bad_data, content_type='multipart/form-data', follow_redirects=True)
    assert response.status_code == 200
    assert b"Invalid file format" in response.data

def test_csv_export_endpoint(client):
    response = client.get("/history/export-csv")
    assert response.status_code == 200
    assert "text/csv" in response.headers["Content-Type"]
