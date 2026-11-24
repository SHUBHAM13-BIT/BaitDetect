import pytest
from analyzer.email_parser import EmailParser, extract_email_address_and_domain

def test_extract_email_address_and_domain():
    res = extract_email_address_and_domain('"Security Team" <security@example.com>')
    assert res["display_name"] == "Security Team"
    assert res["address"] == "security@example.com"
    assert res["domain"] == "example.com"

def test_parse_empty_email():
    res = EmailParser.parse("")
    assert not res["is_valid"]
    assert len(res["errors"]) > 0

def test_parse_simple_rfc822():
    raw = """From: alice@company.com
To: bob@company.com
Subject: Project Update
Date: Tue, 24 Nov 2026 10:00:00 +0000
Message-ID: <msg123@company.com>

Hello Bob, here is the weekly project update.
"""
    res = EmailParser.parse(raw)
    assert res["is_valid"]
    assert res["subject"] == "Project Update"
    assert res["sender_info"]["address"] == "alice@company.com"
    assert "weekly project update" in res["body_plain"]

def test_parse_html_with_links():
    raw = """From: news@service.com
Subject: Newsletter
Content-Type: text/html

<html>
<body>
<p>Visit our site: <a href="https://example.com/login">Log In Here</a></p>
</body>
</html>
"""
    res = EmailParser.parse(raw)
    assert res["is_valid"]
    assert len(res["html_links"]) == 1
    assert res["html_links"][0]["href"] == "https://example.com/login"
    assert res["html_links"][0]["text"] == "Log In Here"
