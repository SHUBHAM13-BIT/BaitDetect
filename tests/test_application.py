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
    assert b"Email Investigation & Security Analysis" in response.data
    assert b"Submit raw emails, RFC 822 files, or email headers for automated threat investigation and security analysis." in response.data

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

def test_upload_valid_eml_file(client):
    eml_content = (
        b"From: \"Security Team\" <security@verified-org.com>\r\n"
        b"To: user@company.com\r\n"
        b"Subject: Monthly Security Bulletin\r\n"
        b"Date: Wed, 25 Nov 2026 09:00:00 +0000\r\n"
        b"Message-ID: <sec-bulletin-01@verified-org.com>\r\n\r\n"
        b"This is the monthly bulletin with safe content.\r\n"
    )
    data = {'email_file': (io.BytesIO(eml_content), 'bulletin.eml')}
    response = client.post('/analyze/submit', data=data, content_type='multipart/form-data', follow_redirects=True)
    assert response.status_code == 200
    assert b"Analysis completed successfully" in response.data

def test_upload_valid_txt_file(client):
    txt_content = (
        b"From: alert@it-helpdesk.com\r\n"
        b"To: target@company.com\r\n"
        b"Subject: Password Expiry Notification\r\n"
        b"Date: Wed, 25 Nov 2026 09:15:00 +0000\r\n\r\n"
        b"Please reset your password at http://198.51.100.22/reset immediately.\r\n"
    )
    data = {'email_file': (io.BytesIO(txt_content), 'password_alert.txt')}
    response = client.post('/analyze/submit', data=data, content_type='multipart/form-data', follow_redirects=True)
    assert response.status_code == 200
    assert b"Analysis completed successfully" in response.data

def test_upload_msg_file_rejection(client):
    data = {'email_file': (io.BytesIO(b"From: test@test.com\r\n\r\nTest"), 'sample.msg')}
    response = client.post('/analyze/submit', data=data, content_type='multipart/form-data', follow_redirects=True)
    assert response.status_code == 200
    assert b"Invalid file format" in response.data
    assert b".eml, .txt" in response.data

def test_upload_unsupported_extensions(client):
    for bad_ext in ['malware.exe', 'document.pdf', 'archive.zip', 'script.py']:
        data = {'email_file': (io.BytesIO(b"data"), bad_ext)}
        response = client.post('/analyze/submit', data=data, content_type='multipart/form-data', follow_redirects=True)
        assert response.status_code == 200
        assert b"Invalid file format" in response.data

def test_upload_empty_file(client):
    data = {'email_file': (io.BytesIO(b""), 'empty_sample.eml')}
    response = client.post('/analyze/submit', data=data, content_type='multipart/form-data', follow_redirects=True)
    assert response.status_code == 200
    assert b"The uploaded file is empty" in response.data

def test_upload_corrupted_email_file(client):
    corrupt_bytes = b"\x00\x01\x02\x03\xff\xfe\x00\x00corrupt-binary-payload"
    data = {'email_file': (io.BytesIO(corrupt_bytes), 'corrupt.eml')}
    response = client.post('/analyze/submit', data=data, content_type='multipart/form-data', follow_redirects=True)
    assert response.status_code == 200
    assert b"Corrupted or unreadable email data" in response.data

def test_upload_binary_msg_ole_magic_rejection(client):
    ole_bytes = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + b"OutlookBinaryMessageStub"
    data = {'email_file': (io.BytesIO(ole_bytes), 'outlook_export.eml')}
    response = client.post('/analyze/submit', data=data, content_type='multipart/form-data', follow_redirects=True)
    assert response.status_code == 200
    assert b"Outlook binary (.msg) format is not supported" in response.data

def test_upload_oversized_file_handler(client):
    from werkzeug.exceptions import RequestEntityTooLarge
    response = client.get("/analyze")
    # Trigger 413 error handler directly to verify response
    with app.test_request_context('/analyze/submit', method='POST'):
        from app import request_entity_too_large
        res = request_entity_too_large(RequestEntityTooLarge())
        assert res.status_code == 302
        assert res.location == "/analyze"

def test_pasted_content_analysis_full_pipeline(client):
    raw_sample = (
        "From: \"Executive Payroll\" <payroll@spoofed-company.xyz>\n"
        "Reply-To: phisher@free-webmail.com\n"
        "To: employee@company.com\n"
        "Subject: Urgent: Verify Direct Deposit Information\n"
        "Date: Wed, 25 Nov 2026 10:00:00 +0000\n"
        "Message-ID: <payroll-notice-99@spoofed-company.xyz>\n\n"
        "Your direct deposit account must be updated within 24 hours.\n"
        "Click here to verify: http://203.0.113.50/payroll/login.php\n"
    )
    # Test submission via form
    response = client.post('/analyze/submit', data={'raw_content': raw_sample}, follow_redirects=True)
    assert response.status_code == 200
    assert b"Analysis completed successfully" in response.data

    # Test submission via JSON API
    api_response = client.post('/api/v1/analyze', json={'raw_content': raw_sample})
    assert api_response.status_code == 200
    data = api_response.get_json()
    assert data["success"] is True
    assert "payroll@spoofed-company.xyz" in data["sender_address"]
    assert "Urgent: Verify Direct Deposit Information" in data["subject"]
    assert data["risk_score"] > 50
    assert len(data["urls"]) > 0
    assert data["threat_category"] is not None
    assert "pdf_report_path" in data

