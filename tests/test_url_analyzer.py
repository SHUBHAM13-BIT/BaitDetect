import pytest
from analyzer.url_analyzer import URLAnalyzer

def test_url_analyzer_ip_host():
    urls = [{"url": "http://198.51.100.12/login.php", "anchor_text": "", "source": "plain_text"}]
    res = URLAnalyzer.analyze(urls)
    assert res["suspicious_urls_count"] == 1
    ind_names = [i["name"] for i in res["indicators"]]
    assert any("Direct IP Address" in name for name in ind_names)

def test_url_analyzer_shortener():
    urls = [{"url": "https://bit.ly/3xyzSecret", "anchor_text": "", "source": "plain_text"}]
    res = URLAnalyzer.analyze(urls)
    assert res["suspicious_urls_count"] == 1
    ind_names = [i["name"] for i in res["indicators"]]
    assert any("URL Shortener" in name for name in ind_names)

def test_url_analyzer_anchor_mismatch():
    urls = [{
        "url": "http://evil-phish.xyz/login",
        "anchor_text": "https://paypal.com/signin",
        "source": "html_anchor"
    }]
    res = URLAnalyzer.analyze(urls)
    assert res["suspicious_urls_count"] == 1
    ind_names = [i["name"] for i in res["indicators"]]
    assert any("Deceptive Hyperlink" in name for name in ind_names)

def test_url_analyzer_typosquatting_brand():
    urls = [{"url": "https://paypal-update-account.xyz/secure", "anchor_text": "", "source": "plain_text"}]
    res = URLAnalyzer.analyze(urls)
    assert res["suspicious_urls_count"] == 1
    ind_names = [i["name"] for i in res["indicators"]]
    assert any("Brand Keyword" in name or "Typosquatting" in name for name in ind_names)
