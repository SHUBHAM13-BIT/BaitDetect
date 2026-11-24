import re
from typing import Dict, List, Any

class ContentAnalyzer:
    """Evaluates email subject and body content using rule-based behavioral and psychological heuristics."""

    CATEGORIES = {
        "urgency_coercion": {
            "name": "Artificial Urgency & Coercive Pressure",
            "weight": 20,
            "severity": "High",
            "patterns": [
                r"\b(?:immediate(?:ly)?|urgent(?:ly)?|urgent action required|take action now)\b",
                r"\bwithin\s+(?:24|12|48|2|1)\s*(?:hours|hrs|days)\b",
                r"\b(?:account|access)\s+(?:will be|has been)\s+(?:suspended|terminated|deactivated|closed|locked)\b",
                r"\bfinal\s+(?:warning|notice|reminder)\b",
                r"\bavoid\s+(?:suspension|deactivation|penalties|legal action)\b",
                r"\bact\s+(?:now|immediately|fast)\s+to\s+prevent\b",
                r"\bfailure\s+to\s+(?:respond|comply|verify)\b"
            ],
            "description": "Uses psychological urgency to trigger panic and bypass critical thinking.",
            "recommended_action": "Pause and verify independently; organizations rarely demand action within 24 hours without prior notice."
        },
        "credential_harvesting": {
            "name": "Credential Harvesting & Re-Authentication Bait",
            "weight": 25,
            "severity": "Critical",
            "patterns": [
                r"\b(?:reset|change|update)\s+your\s+password\b",
                r"\b(?:verify|validate|confirm)\s+your\s+(?:account|identity|credentials|information|profile|mailbox|email)\b",
                r"\b(?:click|tap)\s+here\s+to\s+(?:login|sign in|verify|authenticate|unlock|reactivate)\b",
                r"\bunauthorized\s+(?:login|sign-in|access|device|attempt)\s+detected\b",
                r"\b(?:re-authenticate|re-login|keep your current password)\b",
                r"\bmailbox\s+(?:quota|storage)\s+(?:exceeded|full|limit reached)\b",
                r"\bsecurity\s+alert\s*:\s*(?:unusual activity|compromised)\b"
            ],
            "description": "Direct attempts to deceive the recipient into inputting credentials on a fraudulent landing page.",
            "recommended_action": "Never click email links to change passwords. Go directly to official service portal."
        },
        "fake_payment_invoice": {
            "name": "Fraudulent Invoice & Payment Lure",
            "weight": 20,
            "severity": "High",
            "patterns": [
                r"\b(?:invoice|receipt|billing statement|remittance advice|order confirmation)\s+(?:#|no\.?|[0-9]{3,})\b",
                r"\b(?:payment|amount)\s+(?:overdue|due|pending|declined|failed)\b",
                r"\bwire\s+(?:transfer|funds|instructions)\b",
                r"\b(?:crypto|bitcoin|btc|usdt|ethereum|wallet address)\b",
                r"\byour\s+(?:subscription|order|purchase)\s+has\s+been\s+renewed\b",
                r"\bcharged\s+\$?[0-9]{2,}\.?[0-9]{0,2}\s+to\s+your\s+(?:card|account)\b",
                r"\bdispute\s+this\s+transaction\s+by\s+calling\b"
            ],
            "description": "Fabricated transactions intended to panic victims into downloading malicious receipts or calling fake helpdesks.",
            "recommended_action": "Cross-check accounting records directly with the vendor using known authentic contact numbers."
        },
        "ceo_bec_fraud": {
            "name": "Business Email Compromise (BEC) & Executive Impersonation",
            "weight": 25,
            "severity": "Critical",
            "patterns": [
                r"\bare\s+you\s+(?:available|at your desk|in the office|free right now)\??\b",
                r"\bi\s+(?:need|require)\s+you\s+to\s+handle\s+(?:a|an)\s+(?:confidential|discreet|urgent)\s+request\b",
                r"\bkeep\s+this\s+(?:strictly\s+)?confidential\b",
                r"\bprocessed\s+via\s+(?:wire|ach|swift)\s+today\b",
                r"\bchange\s+of\s+(?:banking|bank\s+account|payment)\s+details\b",
                r"\bpurchase\s+(?:apple|google\s+play|steam|amazon)\s+gift\s+cards\b",
                r"\bi'm\s+in\s+a\s+meeting\s+right\s+now\b"
            ],
            "description": "Signature patterns of Business Email Compromise targeting finance, HR, or subordinate staff.",
            "recommended_action": "Contact the executive or sender directly via phone or in person before processing transactions."
        },
        "lottery_prize_inheritance": {
            "name": "Advance Fee & Lottery Scam Language",
            "weight": 20,
            "severity": "High",
            "patterns": [
                r"\bcongratulations\s*[,!]?\s*you\s+(?:have\s+)?won\b",
                r"\bclaim\s+your\s+(?:prize|award|reward|grant|cash|funds)\b",
                r"\b(?:lottery|sweepstakes|lucky\s+winner)\b",
                r"\b(?:inheritance|beneficiary|next\s+of\s+kin|estate\s+funds)\b",
                r"\bconsignment\s+box\b",
                r"\bunclaimed\s+(?:funds|sum|diplomatic\s+package)\b"
            ],
            "description": "Advance-fee fraud (419 scam) promising massive financial sums in exchange for advance fees or identity info.",
            "recommended_action": "Delete immediately. Legitimate lotteries do not contact unentered participants."
        },
        "generic_impersonal_greeting": {
            "name": "Generic Impersonal Salutation",
            "weight": 8,
            "severity": "Low",
            "patterns": [
                r"\b(?:dear\s+(?:customer|user|client|member|account\s+holder|beneficiary|sir/madam|undisclosed))\b",
                r"\b(?:attention\s*:\s*account\s+holder)\b",
                r"\b(?:hello\s+user)\b"
            ],
            "description": "Bulk phishing templates lack personalized recipient names and rely on generic greetings.",
            "recommended_action": "Verify if the sending institution typically addresses you by full name."
        },
        "evasion_formatting": {
            "name": "Evasion Formatting & Typographic Anomalies",
            "weight": 10,
            "severity": "Medium",
            "patterns": [
                r"[A-Z\s]{15,}", # Excessive all-caps words
                r"(?:!{3,}|\?{3,})", # Excessive exclamation/question marks
                r"(?:p[a4]ssw[o0]rd|v[e3]r[i1]fy|b[a4]nk)", # Leetspeak in security terms
            ],
            "description": "Suspicious formatting, excessive capitalization, or character substitution designed to evade spam filters.",
            "recommended_action": "Treat content as unsolicited promotional or deceptive spam."
        }
    }

    @staticmethod
    def analyze(subject: str, body_plain: str, body_html: str = "") -> Dict[str, Any]:
        """
        Runs rule-based regex analysis across subject and body.
        Provides transparent heuristic scores with evidence.
        Note: Heuristic detection does not provide definitive proof of phishing on its own.
        """
        combined_text = f"{subject}\n{body_plain}"
        indicators = []
        categories_detected = []
        total_heuristic_score = 0

        # Scan each category
        for cat_key, cat_meta in ContentAnalyzer.CATEGORIES.items():
            matched_evidence = []
            for pattern_str in cat_meta["patterns"]:
                matches = re.findall(pattern_str, combined_text, re.IGNORECASE)
                if matches:
                    for m in matches[:2]: # limit evidence items
                        evidence_str = m if isinstance(m, str) else str(m)
                        if evidence_str and evidence_str not in matched_evidence:
                            matched_evidence.append(evidence_str)

            if matched_evidence:
                categories_detected.append(cat_key)
                weight = cat_meta["weight"]
                total_heuristic_score += weight

                indicators.append({
                    "category": "Content",
                    "name": cat_meta["name"],
                    "severity": cat_meta["severity"],
                    "assigned_score": weight,
                    "evidence": f"Matched keywords: '{', '.join(matched_evidence)}'",
                    "description": cat_meta["description"],
                    "recommended_action": cat_meta["recommended_action"]
                })

        # Calculate heuristic risk subscore (capped at 45 to prevent content heuristics alone from dictating critical risk)
        heuristic_score = min(total_heuristic_score, 45)

        return {
            "categories_detected": categories_detected,
            "heuristic_score": heuristic_score,
            "indicators": indicators,
            "disclaimer": "Heuristic content detection evaluates behavioral patterns and provides probabilistic risk indicators, not definitive mathematical proof of malicious intent."
        }
