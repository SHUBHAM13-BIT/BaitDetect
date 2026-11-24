from typing import Dict, List, Any

class RiskEngine:
    """Calculates final transparent risk score (0-100) and deduplicates threat indicators."""

    @staticmethod
    def calculate_risk(indicators: List[Dict[str, Any]], parsed_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Deduplicates indicators, bounds category weights, and computes composite 0-100 score.
        """
        # Deduplicate indicators by name and evidence
        seen_keys = set()
        deduped_indicators: List[Dict[str, Any]] = []

        for ind in indicators:
            key = (ind.get("name", ""), ind.get("evidence", "")[:40])
            if key not in seen_keys:
                seen_keys.add(key)
                deduped_indicators.append(ind)

        # Group indicators by category
        category_scores: Dict[str, int] = {
            "Header": 0,
            "URL": 0,
            "Attachment": 0,
            "Content": 0,
            "ThreatIntel": 0
        }

        category_caps = {
            "Header": 40,
            "URL": 45,
            "Attachment": 45,
            "Content": 35,
            "ThreatIntel": 40
        }

        # Calculate capped category scores to prevent double-counting
        for ind in deduped_indicators:
            cat = ind.get("category", "Content")
            score = ind.get("assigned_score", 0)
            if cat in category_scores:
                category_scores[cat] += score

        capped_header = min(category_scores["Header"], category_caps["Header"])
        capped_url = min(category_scores["URL"], category_caps["URL"])
        capped_attachment = min(category_scores["Attachment"], category_caps["Attachment"])
        capped_content = min(category_scores["Content"], category_caps["Content"])
        capped_intel = min(category_scores["ThreatIntel"], category_caps["ThreatIntel"])

        # Composite score calculation
        # Raw additive score
        raw_composite = capped_header + capped_url + capped_attachment + capped_content + capped_intel

        # If any CRITICAL indicator is present (e.g. Executable attachment, DMARC fail + spoofing, Anchor mismatch),
        # ensure score is at least 65 (High Risk) or 82 (Critical)
        critical_indicators = [ind for ind in deduped_indicators if ind.get("severity") == "Critical"]
        high_indicators = [ind for ind in deduped_indicators if ind.get("severity") == "High"]

        final_score = raw_composite
        if len(critical_indicators) >= 2:
            final_score = max(final_score, 85)
        elif len(critical_indicators) == 1:
            final_score = max(final_score, 70)
        elif len(high_indicators) >= 2:
            final_score = max(final_score, 62)

        # Strictly clamp 0 to 100
        final_score = max(0, min(100, final_score))

        # Risk Level Classification
        if final_score <= 20:
            risk_level = "Safe"
        elif final_score <= 40:
            risk_level = "Moderate"
        elif final_score <= 60:
            risk_level = "Suspicious"
        elif final_score <= 80:
            risk_level = "High Risk"
        else:
            risk_level = "Critical – Potential Phishing"

        # Threat Category Identification
        threat_category = RiskEngine._determine_threat_category(deduped_indicators, final_score)

        # Generate Synthesis Notes
        summary_notes = RiskEngine._generate_summary(
            risk_level, final_score, threat_category, deduped_indicators, parsed_data
        )

        return {
            "risk_score": final_score,
            "risk_level": risk_level,
            "threat_category": threat_category,
            "category_breakdown": {
                "header": capped_header,
                "url": capped_url,
                "attachment": capped_attachment,
                "content": capped_content,
                "threat_intel": capped_intel
            },
            "indicators": deduped_indicators,
            "indicator_counts": {
                "total": len(deduped_indicators),
                "critical": len(critical_indicators),
                "high": len(high_indicators),
                "medium": len([i for i in deduped_indicators if i.get("severity") == "Medium"]),
                "low": len([i for i in deduped_indicators if i.get("severity") == "Low"])
            },
            "summary_notes": summary_notes
        }

    @staticmethod
    def _determine_threat_category(indicators: List[Dict[str, Any]], score: int) -> str:
        if score <= 20:
            return "Legitimate / Low Risk"

        indicator_names = " ".join([i.get("name", "").lower() for i in indicators])

        if "executable" in indicator_names or "double extension" in indicator_names or "macro" in indicator_names:
            return "Malware Delivery Campaign"
        elif "bec" in indicator_names or "executive impersonation" in indicator_names:
            return "Business Email Compromise (BEC)"
        elif "credential" in indicator_names or "anchor text vs href mismatch" in indicator_names:
            return "Credential Harvesting"
        elif "invoice" in indicator_names or "payment" in indicator_names:
            return "Fraudulent Invoice / Financial Scam"
        elif "display name spoofing" in indicator_names or "brand" in indicator_names:
            return "Brand Impersonation & Spoofing"
        elif "lottery" in indicator_names or "prize" in indicator_names:
            return "Advance Fee / Lottery Scam"
        elif score >= 60:
            return "Generic Phishing Attack"
        else:
            return "Suspicious / Unsolicited Message"

    @staticmethod
    def _generate_summary(
        risk_level: str, score: int, category: str,
        indicators: List[Dict[str, Any]], parsed: Dict[str, Any]
    ) -> str:
        subject = parsed.get("subject", "(No Subject)")
        sender = parsed.get("sender_info", {}).get("address", "Unknown")

        if risk_level == "Safe":
            return (
                f"The email '{subject}' from <{sender}> exhibits normal communication patterns with a low risk score "
                f"of {score}/100. No active phishing markers, malicious attachments, or spoofed links were detected. "
                f"Standard email hygiene applies."
            )

        criticals = [i["name"] for i in indicators if i.get("severity") == "Critical"]
        highs = [i["name"] for i in indicators if i.get("severity") == "High"]

        key_findings = criticals + highs
        findings_str = ", ".join(key_findings[:3]) if key_findings else "anomalous heuristics"

        return (
            f"The email '{subject}' from <{sender}> has been evaluated as {risk_level.upper()} "
            f"with a risk score of {score}/100. The primary threat classification is '{category}'. "
            f"Prominent threat indicators include: {findings_str}. "
            f"Recipients are advised not to interact with links or attachments and to verify the request out-of-band."
        )
