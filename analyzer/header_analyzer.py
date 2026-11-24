import re
import ipaddress
from typing import Dict, List, Any, Optional, Tuple

class HeaderAnalyzer:
    """Analyzes email headers for spoofing, authentication anomalies, routing hops, and mismatches."""

    IP_REGEX = re.compile(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b")
    # Popular brands often targeted by display-name spoofing
    WELL_KNOWN_BRANDS = [
        "paypal", "google", "microsoft", "apple", "amazon", "netflix", "facebook",
        "instagram", "meta", "chase", "bank of america", "wellsfargo", "citi",
        "irs", "dhl", "fedex", "ups", "usps", "linkedin", "dropbox", "docu sign",
        "docusign", "coinbase", "binance", "metamask", "whatsapp", "telegram"
    ]

    FREE_MAIL_PROVIDERS = [
        "gmail.com", "yahoo.com", "hotmail.com", "outlook.com", "aol.com",
        "proton.me", "protonmail.com", "zoho.com", "mail.com", "gmx.com", "yandex.com"
    ]

    @staticmethod
    def analyze(parsed_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Runs comprehensive header security analysis.
        Returns extracted headers, authentication breakdown, routing chain, and detected indicators.
        """
        indicators = []
        headers = parsed_data.get("headers", {})
        sender_info = parsed_data.get("sender_info", {})
        reply_to_info = parsed_data.get("reply_to_info", {})
        return_path_info = parsed_data.get("return_path_info", {})
        received_headers = parsed_data.get("received_headers", [])
        auth_results_raw = parsed_data.get("authentication_results", "")

        from_addr = sender_info.get("address", "").lower()
        from_domain = sender_info.get("domain", "").lower()
        from_display = sender_info.get("display_name", "")

        reply_to_addr = reply_to_info.get("address", "").lower()
        reply_to_domain = reply_to_info.get("domain", "").lower()

        return_path_addr = return_path_info.get("address", "").lower()
        return_path_domain = return_path_info.get("domain", "").lower()

        # 1. Parse Authentication-Results (SPF, DKIM, DMARC)
        auth_status = HeaderAnalyzer._parse_authentication_results(auth_results_raw, headers)

        # Record authentication indicators - clearly separating FAIL from MISSING
        # SPF
        if auth_status["spf"]["status"] == "fail":
            indicators.append({
                "category": "Header",
                "name": "SPF Authentication Failed",
                "severity": "High",
                "assigned_score": 25,
                "evidence": f"SPF result: {auth_status['spf'].get('details', 'fail')}",
                "description": "Sender Policy Framework check failed. The sending server is unauthorized by domain policy.",
                "recommended_action": "Treat email with extreme suspicion; verify sender via out-of-band channel."
            })
        elif auth_status["spf"]["status"] == "softfail":
            indicators.append({
                "category": "Header",
                "name": "SPF Authentication Softfail",
                "severity": "Medium",
                "assigned_score": 15,
                "evidence": f"SPF result: {auth_status['spf'].get('details', 'softfail')}",
                "description": "The sending server is probably not authorized by the domain SPF policy.",
                "recommended_action": "Check additional authentication headers and inspect links closely."
            })
        elif auth_status["spf"]["status"] == "missing":
            indicators.append({
                "category": "Header",
                "name": "SPF Authentication Missing",
                "severity": "Low",
                "assigned_score": 8,
                "evidence": "No SPF verification header or record detected in Authentication-Results.",
                "description": "Missing SPF does not confirm phishing but indicates unauthenticated transmission.",
                "recommended_action": "Review sender infrastructure and verify domain reputation."
            })

        # DKIM
        if auth_status["dkim"]["status"] == "fail":
            indicators.append({
                "category": "Header",
                "name": "DKIM Authentication Failed",
                "severity": "High",
                "assigned_score": 25,
                "evidence": f"DKIM result: {auth_status['dkim'].get('details', 'fail')}",
                "description": "Cryptographic signature validation failed or email content was altered in transit.",
                "recommended_action": "Do not trust content or attachments; potential message tampering."
            })
        elif auth_status["dkim"]["status"] == "missing":
            indicators.append({
                "category": "Header",
                "name": "DKIM Signature Missing",
                "severity": "Low",
                "assigned_score": 8,
                "evidence": "No DKIM verification signature detected in headers.",
                "description": "The email does not have a cryptographic DKIM signature verifying message integrity.",
                "recommended_action": "Exercise caution; modern enterprise emails usually carry DKIM signatures."
            })

        # DMARC
        if auth_status["dmarc"]["status"] == "fail":
            indicators.append({
                "category": "Header",
                "name": "DMARC Policy Evaluation Failed",
                "severity": "Critical",
                "assigned_score": 30,
                "evidence": f"DMARC result: {auth_status['dmarc'].get('details', 'fail')}",
                "description": "Domain-based Message Authentication, Reporting, and Conformance policy failed.",
                "recommended_action": "High probability of domain spoofing; reject or quarantine message."
            })
        elif auth_status["dmarc"]["status"] == "missing":
            indicators.append({
                "category": "Header",
                "name": "DMARC Policy Check Missing",
                "severity": "Low",
                "assigned_score": 5,
                "evidence": "No DMARC result header found.",
                "description": "No DMARC evaluation entry found in authentication headers.",
                "recommended_action": "Domain alignment cannot be verified automatically."
            })

        # 2. Check From vs Reply-To Mismatch
        if reply_to_addr and from_addr and (reply_to_addr != from_addr):
            # Check domain mismatch
            if reply_to_domain != from_domain:
                is_freemail_reply = any(reply_to_domain.endswith(prov) for prov in HeaderAnalyzer.FREE_MAIL_PROVIDERS)
                severity = "Critical" if is_freemail_reply else "High"
                score = 30 if is_freemail_reply else 20
                indicators.append({
                    "category": "Header",
                    "name": "Sender and Reply-To Domain Mismatch",
                    "severity": severity,
                    "assigned_score": score,
                    "evidence": f"From: <{from_addr}> vs Reply-To: <{reply_to_addr}>",
                    "description": f"Responses will be diverted to an entirely different domain ({reply_to_domain})." +
                                   (" Notice the Reply-To is a public free-mail service!" if is_freemail_reply else ""),
                    "recommended_action": "Do not reply. Phishers use mismatched Reply-To addresses to harvest direct responses."
                })
            else:
                # Same domain but different mailbox
                indicators.append({
                    "category": "Header",
                    "name": "Sender and Reply-To Address Discrepancy",
                    "severity": "Medium",
                    "assigned_score": 10,
                    "evidence": f"From: <{from_addr}> vs Reply-To: <{reply_to_addr}>",
                    "description": "Reply-To specifies a different mailbox under the same domain.",
                    "recommended_action": "Verify if this matches normal automated ticketing behavior."
                })

        # 3. Check From vs Return-Path Mismatch
        if return_path_domain and from_domain and (return_path_domain != from_domain):
            indicators.append({
                "category": "Header",
                "name": "From and Return-Path Domain Mismatch",
                "severity": "Medium",
                "assigned_score": 12,
                "evidence": f"From domain: '{from_domain}' vs Return-Path domain: '{return_path_domain}'",
                "description": "Bounced messages route to a different domain. Common with bulk mailers but also spoofed campaigns.",
                "recommended_action": "Check SPF alignment with Return-Path domain."
            })

        # 4. Display Name Spoofing / Impersonation
        if from_display and from_domain:
            display_lower = from_display.lower()
            for brand in HeaderAnalyzer.WELL_KNOWN_BRANDS:
                # Check if brand name is in display name, but NOT in from_domain
                if re.search(r"\b" + re.escape(brand) + r"\b", display_lower):
                    brand_clean = brand.replace(" ", "")
                    if brand_clean not in from_domain.replace(".", "").replace("-", ""):
                        indicators.append({
                            "category": "Header",
                            "name": "Display Name Spoofing Detected",
                            "severity": "Critical",
                            "assigned_score": 30,
                            "evidence": f"Display Name: '{from_display}' claiming brand '{brand.title()}' while actual domain is '{from_domain}'",
                            "description": "The sender name impersonates a reputable brand or organization, but the actual sending domain belongs to an unrelated entity.",
                            "recommended_action": "Flag as probable phishing impersonation immediately."
                        })
                        break

            # Also check if display name contains an email address that differs from From address
            embedded_emails = re.findall(r"[\w\.-]+@[\w\.-]+\.\w+", from_display)
            if embedded_emails and embedded_emails[0].lower() != from_addr:
                indicators.append({
                    "category": "Header",
                    "name": "Deceptive Display Name (Embedded Email)",
                    "severity": "High",
                    "assigned_score": 25,
                    "evidence": f"Display Name includes '{embedded_emails[0]}' but real sender is '{from_addr}'",
                    "description": "Attacker attempted to disguise true sender address by embedding a trusted address inside the display name string.",
                    "recommended_action": "Do not trust the apparent sender identity."
                })

        # 5. Received Header Analysis & Routing
        routing_info = HeaderAnalyzer._analyze_received_headers(received_headers)
        sending_ip = routing_info["originating_ip"]

        if routing_info["hop_count"] > 10:
            indicators.append({
                "category": "Header",
                "name": "Anomalous Routing Hop Count",
                "severity": "Medium",
                "assigned_score": 10,
                "evidence": f"Email traversed {routing_info['hop_count']} intermediate relays.",
                "description": "Excessive relay hops may indicate proxy chaining or open relay abuse.",
                "recommended_action": "Inspect intermediate server hostnames in routing chain."
            })

        # Check sending IP reputation / private IP anomalies
        if sending_ip:
            try:
                ip_obj = ipaddress.ip_address(sending_ip)
                if ip_obj.is_private or ip_obj.is_reserved or ip_obj.is_loopback:
                    indicators.append({
                        "category": "Header",
                        "name": "Internal/Private Originating IP in Header",
                        "severity": "Low",
                        "assigned_score": 5,
                        "evidence": f"Earliest IP identified: {sending_ip} (Private/Local)",
                        "description": "The message appears to originate from an internal LAN or test harness.",
                        "recommended_action": "Verify if sent within corporate intranet."
                    })
            except Exception:
                pass

        # 6. Missing Message-ID or Invalid Format
        message_id = parsed_data.get("message_id", "")
        if not message_id:
            indicators.append({
                "category": "Header",
                "name": "Missing Message-ID Header",
                "severity": "Medium",
                "assigned_score": 12,
                "evidence": "No Message-ID header present.",
                "description": "RFC 5322 requires a Message-ID header. Automated spam and phishing tools frequently omit this header.",
                "recommended_action": "Inspect sending MTA configuration."
            })
        elif "@" not in message_id or not message_id.startswith("<") or not message_id.endswith(">"):
            indicators.append({
                "category": "Header",
                "name": "Malformed Message-ID Header",
                "severity": "Low",
                "assigned_score": 6,
                "evidence": f"Message-ID: '{message_id}' does not conform to standard format <uuid@domain>.",
                "description": "Non-standard Message-ID may indicate custom or poorly constructed mail generator scripts.",
                "recommended_action": "Verify authenticity of mail server software."
            })

        return {
            "auth_status": auth_status,
            "routing": routing_info,
            "sending_ip": sending_ip or "Not detected",
            "from_domain": from_domain,
            "reply_to_domain": reply_to_domain,
            "return_path_domain": return_path_domain,
            "indicators": indicators
        }

    @staticmethod
    def _parse_authentication_results(auth_header: str, headers: Dict[str, Any]) -> Dict[str, Any]:
        """
        Parses Authentication-Results and standalone headers like Received-SPF, DKIM-Signature.
        Returns explicit status for SPF, DKIM, and DMARC.
        """
        result = {
            "spf": {"status": "missing", "details": "No SPF record in headers"},
            "dkim": {"status": "missing", "details": "No DKIM record in headers"},
            "dmarc": {"status": "missing", "details": "No DMARC record in headers"}
        }

        # Check standalone headers first
        received_spf = headers.get("received-spf", "")
        if isinstance(received_spf, list):
            received_spf = " ".join(received_spf)
        if received_spf:
            spf_lower = received_spf.lower()
            if "pass" in spf_lower:
                result["spf"] = {"status": "pass", "details": received_spf[:150]}
            elif "fail" in spf_lower and "softfail" not in spf_lower:
                result["spf"] = {"status": "fail", "details": received_spf[:150]}
            elif "softfail" in spf_lower:
                result["spf"] = {"status": "softfail", "details": received_spf[:150]}
            elif "neutral" in spf_lower:
                result["spf"] = {"status": "neutral", "details": received_spf[:150]}
            elif "none" in spf_lower:
                result["spf"] = {"status": "none", "details": received_spf[:150]}

        dkim_sig = headers.get("dkim-signature", "")
        if dkim_sig and result["dkim"]["status"] == "missing":
            result["dkim"] = {"status": "present", "details": "DKIM-Signature present; verification pending server auth"}

        # Parse Authentication-Results header if present
        if auth_header:
            auth_lower = auth_header.lower()

            # SPF in Authentication-Results
            spf_match = re.search(r"spf=([a-z]+)(?:\s+\(([^)]+)\))?", auth_lower)
            if spf_match:
                spf_val = spf_match.group(1)
                details = spf_match.group(2) or spf_val
                result["spf"] = {"status": spf_val, "details": f"spf={spf_val} ({details})"}

            # DKIM in Authentication-Results
            dkim_match = re.search(r"dkim=([a-z]+)(?:\s+\(([^)]+)\))?", auth_lower)
            if dkim_match:
                dkim_val = dkim_match.group(1)
                details = dkim_match.group(2) or dkim_val
                result["dkim"] = {"status": dkim_val, "details": f"dkim={dkim_val} ({details})"}

            # DMARC in Authentication-Results
            dmarc_match = re.search(r"dmarc=([a-z]+)(?:\s+\(([^)]+)\))?", auth_lower)
            if dmarc_match:
                dmarc_val = dmarc_match.group(1)
                details = dmarc_match.group(2) or dmarc_val
                result["dmarc"] = {"status": dmarc_val, "details": f"dmarc={dmarc_val} ({details})"}

        return result

    @staticmethod
    def _analyze_received_headers(received_headers: List[str]) -> Dict[str, Any]:
        """
        Parses Received headers from bottom (origin) to top (destination).
        Extracts relay hops, timestamps, and originating sending IP.
        """
        hops = []
        originating_ip = None

        # Received headers are prepended by each server, so the bottom-most header is earliest
        for idx, line in enumerate(reversed(received_headers)):
            ips = HeaderAnalyzer.IP_REGEX.findall(line)
            # Find public IP if possible
            hop_ip = None
            for candidate in ips:
                try:
                    ip_obj = ipaddress.ip_address(candidate)
                    if not hop_ip:
                        hop_ip = candidate
                    if not (ip_obj.is_private or ip_obj.is_reserved or ip_obj.is_loopback):
                        hop_ip = candidate
                        break
                except ValueError:
                    continue

            if not originating_ip and hop_ip:
                originating_ip = hop_ip

            # Extract server by/from strings
            from_match = re.search(r"from\s+([^\s;]+)", line, re.IGNORECASE)
            by_match = re.search(r"by\s+([^\s;]+)", line, re.IGNORECASE)

            from_host = from_match.group(1) if from_match else "Unknown"
            by_host = by_match.group(1) if by_match else "Unknown"

            hops.append({
                "hop_number": idx + 1,
                "from_host": from_host,
                "by_host": by_host,
                "ip": hop_ip or "None",
                "raw_snippet": line[:150]
            })

        return {
            "hop_count": len(received_headers),
            "originating_ip": originating_ip,
            "hops": hops
        }
