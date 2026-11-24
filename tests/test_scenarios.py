import pytest
import io
from analyzer.pipeline import AnalysisPipeline
from analyzer.email_parser import EmailParser
from analyzer.threat_intelligence import ThreatIntelligence
from reports.report_generator import ReportGenerator

# Scenario 1: Normal Legitimate Email
def test_scenario_01_normal_legitimate_email():
    raw = """From: "GitHub" <notifications@github.com>
To: user@company.com
Reply-To: support@github.com
Subject: [GitHub] Security alert for repository
Date: Tue, 24 Nov 2026 12:00:00 +0000
Message-ID: <valid-uuid-12345@github.com>
Authentication-Results: mx.google.com; spf=pass; dkim=pass; dmarc=pass

Hi user, Dependabot detected a vulnerability. Review details at https://github.com/security.
"""
    res = AnalysisPipeline.process_email(raw)
    assert res["success"]
    assert res["risk_level"] in ("Safe", "Moderate")
    assert res["spf_status"] == "pass"
    assert res["dkim_status"] == "pass"

# Scenario 2: Suspicious Sender Address (Free-mail claiming to be enterprise or weird TLD)
def test_scenario_02_suspicious_sender_address():
    raw = """From: "Microsoft Support Desk" <msft-security-update@random-suspicious.xyz>
To: victim@company.com
Subject: Action Required
Date: Tue, 24 Nov 2026 12:00:00 +0000
Message-ID: <sec991@random-suspicious.xyz>

Please verify your credentials immediately.
"""
    res = AnalysisPipeline.process_email(raw)
    assert res["success"]
    ind_names = [i["name"] for i in res["indicators"]]
    assert any("Display Name Spoofing" in n or "Credential Harvesting" in n for n in ind_names)

# Scenario 3: Fake Password Reset Email
def test_scenario_03_fake_password_reset_email():
    raw = """From: IT Helpdesk <admin@company-support-reset.xyz>
To: employee@company.com
Subject: Password Expired - Reset Immediately
Date: Tue, 24 Nov 2026 12:00:00 +0000
Message-ID: <pwd9982@company-support-reset.xyz>

Your network password will expire in 2 hours.
Click here to verify and reset your password immediately:
http://198.51.100.22/reset-password
"""
    res = AnalysisPipeline.process_email(raw)
    assert res["success"]
    assert res["risk_score"] >= 60
    ind_names = [i["name"] for i in res["indicators"]]
    assert any("Credential Harvesting" in n for n in ind_names)
    assert any("Direct IP Address" in n for n in ind_names)

# Scenario 4: Suspicious URL
def test_scenario_04_suspicious_url():
    raw = """From: notice@service.com
Subject: Payment Issue
Date: Tue, 24 Nov 2026 12:00:00 +0000
Message-ID: <pay001@service.com>

Review your account at: http://paypal.com.account-update.xyz/verify
"""
    res = AnalysisPipeline.process_email(raw)
    assert res["success"]
    assert res["suspicious_url_count"] >= 1
    assert any(u["is_suspicious"] for u in res["urls"])

# Scenario 5: URL Shortener
def test_scenario_05_url_shortener():
    raw = """From: colleague@partner.com
Subject: Shared Document
Date: Tue, 24 Nov 2026 12:00:00 +0000
Message-ID: <doc77@partner.com>

Please review this file: https://bit.ly/3SecretPayroll
"""
    res = AnalysisPipeline.process_email(raw)
    assert res["success"]
    ind_names = [i["name"] for i in res["indicators"]]
    assert any("URL Shortener" in n for n in ind_names)

# Scenario 6: Sender and Reply-To Mismatch
def test_scenario_06_sender_reply_to_mismatch():
    raw = """From: "Bank of America" <support@bankofamerica.com>
Reply-To: phisher-collect@gmail.com
Subject: Account Update
Date: Tue, 24 Nov 2026 12:00:00 +0000
Message-ID: <boa001@boa.com>

Reply with your account number to update your profile.
"""
    res = AnalysisPipeline.process_email(raw)
    assert res["success"]
    ind_names = [i["name"] for i in res["indicators"]]
    assert any("Sender and Reply-To Domain Mismatch" in n for n in ind_names)

# Scenario 7: Missing SPF Information
def test_scenario_07_missing_spf():
    raw = """From: sender@unknown-small-domain.org
Subject: Hello
Date: Tue, 24 Nov 2026 12:00:00 +0000
Message-ID: <msg441@unknown.org>

Just a quick hello note.
"""
    res = AnalysisPipeline.process_email(raw)
    assert res["success"]
    assert res["spf_status"] == "missing"

# Scenario 8: Failed DKIM Authentication
def test_scenario_08_failed_dkim():
    raw = """From: billing@vendor.com
Subject: Invoice
Date: Tue, 24 Nov 2026 12:00:00 +0000
Message-ID: <inv881@vendor.com>
Authentication-Results: mx.google.com; spf=pass; dkim=fail (body hash mismatch); dmarc=fail

Here is your monthly invoice.
"""
    res = AnalysisPipeline.process_email(raw)
    assert res["success"]
    assert res["dkim_status"] == "fail"
    ind_names = [i["name"] for i in res["indicators"]]
    assert any("DKIM Authentication Failed" in n for n in ind_names)

# Scenario 9: Suspicious Attachment Filename (Double Extension)
def test_scenario_09_suspicious_attachment():
    raw = """From: billing@supplier.com
Subject: Overdue Bill
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="BOUNDARY123"

--BOUNDARY123
Content-Type: text/plain

Please find invoice attached.
--BOUNDARY123
Content-Type: application/octet-stream; name="Invoice_Report.pdf.exe"
Content-Disposition: attachment; filename="Invoice_Report.pdf.exe"

TVqQAAMAAAAEAAAA//8AALgAAAAAAAAAQAA=
--BOUNDARY123--
"""
    res = AnalysisPipeline.process_email(raw)
    assert res["success"]
    assert res["attachment_count"] == 1
    assert res["suspicious_attachment_count"] == 1
    ind_names = [i["name"] for i in res["indicators"]]
    assert any("Double Extension" in n or "Executable" in n for n in ind_names)

# Scenario 10: Empty Email Input
def test_scenario_10_empty_email_input():
    res = AnalysisPipeline.process_email("")
    assert not res["success"]
    assert "Empty input" in res["error"]

# Scenario 11: Invalid Uploaded File (Blank or non-text binary)
def test_scenario_11_invalid_file():
    res = AnalysisPipeline.process_email(b"\x00\x00\x00\x00")
    # Should handle without crashing
    assert isinstance(res, dict)

# Scenario 12: Corrupted EML File (Mangled boundaries)
def test_scenario_12_corrupted_eml():
    raw = """From: corrupted@domain.com
Subject: Broken Multipart
Content-Type: multipart/mixed; boundary="MISSING_BOUNDARY"

This body has no matching boundaries and is corrupted.
"""
    res = AnalysisPipeline.process_email(raw)
    assert res["success"] # Gracefully falls back to body parsing
    assert res["sender_address"] == "corrupted@domain.com"

# Scenario 13: Large Email Content (e.g. 500KB text)
def test_scenario_13_large_email_content():
    large_body = "Urgent notice! " * 20000
    raw = f"From: hr@company.com\nSubject: Important\n\n{large_body}"
    res = AnalysisPipeline.process_email(raw)
    assert res["success"]
    assert res["metadata"]["body_length_chars"] > 100000

# Scenario 14: API Unavailable (VirusTotal unconfigured or offline)
def test_scenario_14_api_unavailable():
    res = ThreatIntelligence.check_virustotal("http://example.com")
    assert res["status"] in ("pending_configuration", "clean", "unknown", "error")

# Scenario 15: Network Unavailable (DNS lookup fallback)
def test_scenario_15_network_unavailable():
    # Query non-resolvable domain with DNS timeout
    res = ThreatIntelligence.query_dns_records("nonexistent-domain-test-xyz-987.invalid")
    assert res["dns_lookup_status"] == "completed"
    assert res["spf_record"] is None
    assert res["dmarc_record"] is None
