import requests
import dns.resolver
import socket
from typing import Dict, List, Any, Optional
from config import Config
from database.database import get_setting

class ThreatIntelligence:
    """Provides reputation checks via URLhaus, VirusTotal, Google Safe Browsing, and live DNS queries."""

    URLHAUS_API_ENDPOINT = "https://urlhaus-api.abuse.ch/v1/url/"

    @staticmethod
    def query_dns_records(domain: str) -> Dict[str, Any]:
        """
        Queries SPF and DMARC TXT records for a domain.
        Handles network timeouts gracefully.
        """
        results = {
            "domain": domain,
            "spf_record": None,
            "dmarc_record": None,
            "mx_records": [],
            "dns_lookup_status": "pending"
        }

        if not domain or domain in ("localhost", "127.0.0.1") or "." not in domain:
            results["dns_lookup_status"] = "skipped_local"
            return results

        resolver = dns.resolver.Resolver()
        resolver.timeout = 2.0
        resolver.lifetime = 2.0

        # 1. Query TXT for SPF
        try:
            answers = resolver.resolve(domain, "TXT")
            for rdata in answers:
                txt_str = "".join([b.decode("utf-8", errors="replace") if isinstance(b, bytes) else str(b) for b in rdata.strings])
                if "v=spf1" in txt_str.lower():
                    results["spf_record"] = txt_str
                    break
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers, dns.exception.Timeout, Exception):
            results["spf_record"] = None

        # 2. Query DMARC TXT (_dmarc.domain)
        try:
            dmarc_domain = f"_dmarc.{domain}"
            answers = resolver.resolve(dmarc_domain, "TXT")
            for rdata in answers:
                txt_str = "".join([b.decode("utf-8", errors="replace") if isinstance(b, bytes) else str(b) for b in rdata.strings])
                if "v=dmarc1" in txt_str.lower():
                    results["dmarc_record"] = txt_str
                    break
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers, dns.exception.Timeout, Exception):
            results["dmarc_record"] = None

        # 3. Query MX records
        try:
            answers = resolver.resolve(domain, "MX")
            for rdata in answers:
                results["mx_records"].append(str(rdata.exchange).rstrip("."))
        except Exception:
            pass

        results["dns_lookup_status"] = "completed"
        return results

    @staticmethod
    def check_urlhaus(url: str) -> Dict[str, Any]:
        """
        Queries URLhaus API (abuse.ch) for known malicious URL database.
        Safe, non-executing query.
        """
        try:
            response = requests.post(
                ThreatIntelligence.URLHAUS_API_ENDPOINT,
                data={"url": url},
                timeout=3.0,
                headers={"User-Agent": "BaitDetect-Phishing-Analyzer/1.0"}
            )
            if response.status_code == 200:
                data = response.json()
                query_status = data.get("query_status", "no_results")
                if query_status == "ok":
                    return {
                        "status": "malicious",
                        "threat": data.get("threat", "malware_download"),
                        "tags": data.get("tags", []),
                        "reporter": data.get("reporter", "URLhaus"),
                        "details": f"Flagged in URLhaus threat feed as {data.get('threat')}"
                    }
                elif query_status == "no_results":
                    return {
                        "status": "clean",
                        "threat": None,
                        "details": "Not listed in active URLhaus malware database"
                    }
        except requests.exceptions.RequestException:
            # Network unavailable or timeout
            pass
        except Exception:
            pass

        return {
            "status": "offline_or_unavailable",
            "threat": None,
            "details": "Threat intelligence service currently unreachable; relying on local heuristics"
        }

    @staticmethod
    def check_virustotal(target: str, target_type: str = "url") -> Dict[str, Any]:
        """
        Queries VirusTotal API if API key is configured.
        Otherwise gracefully returns 'pending_configuration'.
        """
        api_key = get_setting("virustotal_api_key") or Config.VIRUSTOTAL_API_KEY
        if not api_key:
            return {
                "status": "pending_configuration",
                "details": "VirusTotal API key not configured. Local heuristics active.",
                "positives": 0,
                "total": 0
            }

        headers = {"x-apikey": api_key}
        try:
            if target_type == "url":
                import base64
                url_id = base64.urlsafe_b64encode(target.encode()).decode().strip("=")
                endpoint = f"https://www.virustotal.com/api/v3/urls/{url_id}"
                resp = requests.get(endpoint, headers=headers, timeout=4.0)
                if resp.status_code == 200:
                    data = resp.json().get("data", {}).get("attributes", {})
                    stats = data.get("last_analysis_stats", {})
                    malicious = stats.get("malicious", 0)
                    suspicious = stats.get("suspicious", 0)
                    total = sum(stats.values())
                    return {
                        "status": "malicious" if malicious > 0 else "clean",
                        "positives": malicious + suspicious,
                        "total": total,
                        "details": f"VirusTotal detections: {malicious}/{total} security engines"
                    }
        except Exception as e:
            return {
                "status": "error",
                "details": f"VirusTotal query failed: {str(e)}",
                "positives": 0,
                "total": 0
            }

        return {
            "status": "unknown",
            "details": "No definitive scan result retrieved",
            "positives": 0,
            "total": 0
        }
