import pytest
from analyzer.risk_engine import RiskEngine

def test_risk_engine_low_risk_clean():
    indicators = []
    parsed = {"subject": "Lunch meeting", "sender_info": {"address": "colleague@company.com"}}
    res = RiskEngine.calculate_risk(indicators, parsed)
    assert res["risk_score"] == 0
    assert res["risk_level"] == "Safe"

def test_risk_engine_critical_override():
    indicators = [
        {
            "category": "Attachment",
            "name": "High-Risk Executable Attachment (.exe)",
            "severity": "Critical",
            "assigned_score": 35,
            "evidence": "malware.exe",
            "description": "desc",
            "recommended_action": "act"
        },
        {
            "category": "URL",
            "name": "Deceptive Hyperlink (Anchor Text vs Href Mismatch)",
            "severity": "Critical",
            "assigned_score": 35,
            "evidence": "mismatch",
            "description": "desc",
            "recommended_action": "act"
        }
    ]
    parsed = {"subject": "URGENT", "sender_info": {"address": "evil@hacker.xyz"}}
    res = RiskEngine.calculate_risk(indicators, parsed)
    assert res["risk_score"] >= 85
    assert "Critical" in res["risk_level"]

def test_risk_engine_deduplication():
    # Duplicate indicators
    ind = {
        "category": "Header",
        "name": "SPF Authentication Failed",
        "severity": "High",
        "assigned_score": 25,
        "evidence": "SPF failed: 1.2.3.4 not allowed",
        "description": "desc",
        "recommended_action": "act"
    }
    indicators = [ind, ind] # Repeated
    parsed = {"subject": "Test", "sender_info": {"address": "test@test.com"}}
    res = RiskEngine.calculate_risk(indicators, parsed)
    assert res["indicator_counts"]["total"] == 1
