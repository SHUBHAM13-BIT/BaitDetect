import pytest
from analyzer.email_parser import EmailParser
from analyzer.header_analyzer import HeaderAnalyzer

def test_header_analyzer_reply_to_mismatch():
    raw = """From: "PayPal" <support@paypal.com>
Reply-To: scammer@gmail.com
Subject: Account Verification
Date: Tue, 24 Nov 2026 12:00:00 +0000
Message-ID: <12345@scam.com>
"""
    parsed = EmailParser.parse(raw)
    analysis = HeaderAnalyzer.analyze(parsed)
    ind_names = [i["name"] for i in analysis["indicators"]]
    assert any("Reply-To" in name for name in ind_names)

def test_header_analyzer_display_name_spoofing():
    raw = """From: "Google Security Team" <hacker@evil-domain-123.com>
Subject: Security Alert
Date: Tue, 24 Nov 2026 12:00:00 +0000
Message-ID: <123@evil.com>
"""
    parsed = EmailParser.parse(raw)
    analysis = HeaderAnalyzer.analyze(parsed)
    ind_names = [i["name"] for i in analysis["indicators"]]
    assert any("Display Name Spoofing" in name for name in ind_names)

def test_header_analyzer_auth_separation_fail_vs_missing():
    # Email with explicit SPF failure
    raw_fail = """From: user@example.com
Authentication-Results: mx.test.com; spf=fail (IP 1.2.3.4 not authorized); dkim=fail; dmarc=fail
"""
    parsed_fail = EmailParser.parse(raw_fail)
    analysis_fail = HeaderAnalyzer.analyze(parsed_fail)
    auth_fail = analysis_fail["auth_status"]
    assert auth_fail["spf"]["status"] == "fail"
    assert auth_fail["dkim"]["status"] == "fail"
    assert auth_fail["dmarc"]["status"] == "fail"

    # Email with NO authentication headers (missing)
    raw_missing = """From: user@example.com
Subject: Simple Note
Date: Tue, 24 Nov 2026 12:00:00 +0000
Message-ID: <note123@example.com>
"""
    parsed_missing = EmailParser.parse(raw_missing)
    analysis_missing = HeaderAnalyzer.analyze(parsed_missing)
    auth_missing = analysis_missing["auth_status"]
    assert auth_missing["spf"]["status"] == "missing"
    assert auth_missing["dkim"]["status"] == "missing"
    assert auth_missing["dmarc"]["status"] == "missing"
