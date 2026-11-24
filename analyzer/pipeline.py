import uuid
import datetime
from typing import Dict, Any, Optional
from analyzer.email_parser import EmailParser
from analyzer.header_analyzer import HeaderAnalyzer
from analyzer.url_analyzer import URLAnalyzer
from analyzer.attachment_analyzer import AttachmentAnalyzer
from analyzer.content_analyzer import ContentAnalyzer
from analyzer.threat_intelligence import ThreatIntelligence
from analyzer.risk_engine import RiskEngine

class AnalysisPipeline:
    """Master orchestrator connecting all analysis modules into a unified pipeline."""

    @staticmethod
    def process_email(raw_input: Any, generate_id: bool = True) -> Dict[str, Any]:
        """
        Executes end-to-end phishing analysis on raw email string, bytes, or headers.
        """
        if not raw_input:
            return {
                "success": False,
                "error": "Empty input provided. Please paste email content or upload an email file."
            }

        # 1. Parse Email
        parsed = EmailParser.parse(raw_input)
        if not parsed.get("is_valid"):
            err_msg = ", ".join(parsed.get("errors", ["Invalid email content."]))
            return {
                "success": False,
                "error": f"Failed to parse email: {err_msg}"
            }

        # 2. Header Analysis
        header_results = HeaderAnalyzer.analyze(parsed)

        # 3. Live DNS Intelligence (Sender Domain)
        sender_domain = parsed.get("sender_info", {}).get("domain", "")
        dns_results = ThreatIntelligence.query_dns_records(sender_domain)

        # 4. URL Extraction & Analysis
        raw_urls = URLAnalyzer.extract_urls(parsed.get("body_plain", ""), parsed.get("html_links", []))
        url_results = URLAnalyzer.analyze(raw_urls)

        # Threat Intelligence check on extracted URLs (safe non-executing)
        for u in url_results.get("urls", []):
            u_str = u.get("url", "")
            # URLhaus check
            uh_res = ThreatIntelligence.check_urlhaus(u_str)
            u["threat_intel_urlhaus"] = uh_res
            if uh_res.get("status") == "malicious":
                url_results["indicators"].append({
                    "category": "ThreatIntel",
                    "name": "URL Listed in Threat Intelligence Feed (URLhaus)",
                    "severity": "Critical",
                    "assigned_score": 35,
                    "evidence": f"URL: {u_str} | Threat: {uh_res.get('threat')}",
                    "description": "The URL is actively listed in the URLhaus malware & phishing database.",
                    "recommended_action": "Block URL at perimeter proxy and firewall."
                })

        # 5. Attachment Analysis
        attachment_results = AttachmentAnalyzer.analyze(parsed.get("attachments", []))

        # 6. Content Analysis
        content_results = ContentAnalyzer.analyze(
            parsed.get("subject", ""),
            parsed.get("body_plain", ""),
            parsed.get("body_html", "")
        )

        # 7. Aggregate all indicators
        all_indicators = []
        all_indicators.extend(header_results.get("indicators", []))
        all_indicators.extend(url_results.get("indicators", []))
        all_indicators.extend(attachment_results.get("indicators", []))
        all_indicators.extend(content_results.get("indicators", []))

        # 8. Risk Engine Scoring
        risk_evaluation = RiskEngine.calculate_risk(all_indicators, parsed)

        # 9. Structure Final Output
        now_utc = datetime.datetime.now(datetime.timezone.utc)
        analysis_id = f"ANL-{now_utc.strftime('%Y%m%d')}-{uuid.uuid4().hex[:6].upper()}" if generate_id else ""

        # Distinguish authentication summary
        auth_status = header_results.get("auth_status", {})
        spf_stat = auth_status.get("spf", {}).get("status", "missing")
        dkim_stat = auth_status.get("dkim", {}).get("status", "missing")
        dmarc_stat = auth_status.get("dmarc", {}).get("status", "missing")

        return {
            "success": True,
            "id": analysis_id,
            "created_at": now_utc.isoformat(),
            "created_at_formatted": now_utc.strftime("%Y-%m-%d %H:%M:%S UTC"),
            "metadata": {
                "subject": parsed.get("subject"),
                "date_header": parsed.get("date"),
                "message_id": parsed.get("message_id"),
                "delivered_to": parsed.get("delivered_to"),
                "x_mailer": parsed.get("x_mailer"),
                "has_html": bool(parsed.get("body_html")),
                "body_length_chars": len(parsed.get("body_plain", ""))
            },
            "sender": parsed.get("from_raw", ""),
            "sender_display_name": parsed.get("sender_info", {}).get("display_name", ""),
            "sender_address": parsed.get("sender_info", {}).get("address", ""),
            "sender_domain": sender_domain,
            "reply_to": parsed.get("reply_to_raw", ""),
            "reply_to_address": parsed.get("reply_to_info", {}).get("address", ""),
            "return_path": parsed.get("return_path_raw", ""),
            "return_path_address": parsed.get("return_path_info", {}).get("address", ""),
            "subject": parsed.get("subject"),
            "date_header": parsed.get("date"),
            "message_id": parsed.get("message_id"),
            "sending_ip": header_results.get("sending_ip", "Not detected"),
            "routing_hops": header_results.get("routing", {}).get("hop_count", 0),
            "routing_summary": header_results.get("routing", {}).get("hops", []),
            "body_preview": (parsed.get("body_plain", "") or parsed.get("body_html", ""))[:400],
            "body_full": parsed.get("body_plain", ""),
            "spf_status": spf_stat,
            "dkim_status": dkim_stat,
            "dmarc_status": dmarc_stat,
            "auth_summary": auth_status,
            "dns_records": dns_results,
            "url_count": url_results.get("total_urls", 0),
            "suspicious_url_count": url_results.get("suspicious_urls_count", 0),
            "urls": url_results.get("urls", []),
            "attachment_count": attachment_results.get("total_attachments", 0),
            "suspicious_attachment_count": attachment_results.get("suspicious_attachments_count", 0),
            "attachments": attachment_results.get("attachments", []),
            "content_indicators": content_results.get("indicators", []),
            "indicators": risk_evaluation.get("indicators", []),
            "total_indicators_count": risk_evaluation.get("indicator_counts", {}).get("total", 0),
            "indicator_counts": risk_evaluation.get("indicator_counts", {}),
            "risk_score": risk_evaluation.get("risk_score", 0),
            "risk_level": risk_evaluation.get("risk_level", "Safe"),
            "threat_category": risk_evaluation.get("threat_category", "Standard Email"),
            "category_breakdown": risk_evaluation.get("category_breakdown", {}),
            "summary_notes": risk_evaluation.get("summary_notes", ""),
            "raw_email_preview": parsed.get("raw_content_preview", "")
        }
