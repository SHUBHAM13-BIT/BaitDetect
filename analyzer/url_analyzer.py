import re
import urllib.parse
import ipaddress
from typing import Dict, List, Any, Set, Tuple

class URLAnalyzer:
    """Extracts, parses, and performs deep static cybersecurity inspection on URLs."""

    URL_REGEX = re.compile(
        r"""(?i)\b((?:https?://|www\d{0,3}[.]|[a-z0-9.\-]+[.][a-z]{2,4}/)(?:[^\s()<>]+|\(([^\s()<>]+|(\([^\s()<>]+\)))*\))+(?:\(([^\s()<>]+|(\([^\s()<>]+\)))*\)|[^\s`!()\[\]{};:'".,<>?«»“”‘’]))""",
        re.VERBOSE
    )

    SHORTENER_DOMAINS = {
        "bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "buff.ly", "ow.ly",
        "rebrand.ly", "cutt.ly", "rb.gy", "shorturl.at", "bl.ink", "tiny.cc",
        "qr.net", "v.gd", "soo.gd", "s.id"
    }

    SUSPICIOUS_TLDS = {
        ".xyz", ".top", ".buzz", ".club", ".work", ".loan", ".gq", ".tk", ".ml",
        ".cf", ".ga", ".fit", ".rest", ".bar", ".surf", ".monster", ".click",
        ".country", ".stream", ".download", ".racing", ".link"
    }

    TARGET_BRANDS = [
        "paypal", "google", "microsoft", "apple", "amazon", "netflix",
        "facebook", "instagram", "chase", "wellsfargo", "bankofamerica",
        "citibank", "outlook", "office365", "docusign", "dropbox", "coinbase",
        "binance", "metamask", "blockchain", "irs", "usps", "fedex", "dhl"
    ]

    HOMOGRAPH_LOOKALIKES = {
        'а': 'a', 'с': 'c', 'е': 'e', 'о': 'o', 'р': 'p', 'ѕ': 's', 'х': 'x', 'у': 'y',
        'і': 'i', 'ј': 'j', 'ӏ': 'l', 'ո': 'n', '0': 'o', '1': 'l'
    }

    @staticmethod
    def extract_urls(plain_text: str, html_links: List[Dict[str, str]] = None) -> List[Dict[str, Any]]:
        """
        Extracts all URLs from text and HTML, noting anchor text and mismatches.
        """
        seen_urls: Set[str] = set()
        extracted: List[Dict[str, Any]] = []

        # 1. Process HTML links first (href vs anchor)
        if html_links:
            for link in html_links:
                href = link.get("href", "").strip()
                anchor_text = link.get("text", "").strip()
                if href and href not in seen_urls:
                    seen_urls.add(href)
                    extracted.append({
                        "url": href,
                        "source": "html_anchor",
                        "anchor_text": anchor_text
                    })

        # 2. Extract regex matches from plain text
        if plain_text:
            matches = URLAnalyzer.URL_REGEX.findall(plain_text)
            for m in matches:
                url_str = m[0].strip()
                if not url_str.startswith("http://") and not url_str.startswith("https://"):
                    url_str = "http://" + url_str
                if url_str not in seen_urls:
                    seen_urls.add(url_str)
                    extracted.append({
                        "url": url_str,
                        "source": "plain_text",
                        "anchor_text": ""
                    })

        return extracted

    @staticmethod
    def analyze(urls_data: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Deeply inspects each extracted URL. Never executes or fetches the URLs.
        """
        analyzed_urls = []
        indicators = []
        suspicious_count = 0

        for item in urls_data:
            raw_url = item["url"]
            anchor = item.get("anchor_text", "")
            source = item.get("source", "plain_text")

            url_analysis = URLAnalyzer._inspect_single_url(raw_url, anchor)
            analyzed_urls.append(url_analysis)

            if url_analysis["is_suspicious"]:
                suspicious_count += 1

            # Accumulate indicators
            for ind in url_analysis["indicators"]:
                indicators.append(ind)

        return {
            "total_urls": len(analyzed_urls),
            "suspicious_urls_count": suspicious_count,
            "urls": analyzed_urls,
            "indicators": indicators
        }

    @staticmethod
    def _inspect_single_url(url: str, anchor_text: str = "") -> Dict[str, Any]:
        indicators = []
        is_suspicious = False
        reasons = []

        try:
            parsed = urllib.parse.urlparse(url)
        except Exception:
            return {
                "url": url,
                "is_suspicious": True,
                "reasons": ["Malformed URL syntax"],
                "indicators": [{
                    "category": "URL",
                    "name": "Malformed URL Syntax",
                    "severity": "Medium",
                    "assigned_score": 10,
                    "evidence": url[:100],
                    "description": "The URL cannot be parsed by standard RFC 3986 parsers.",
                    "recommended_action": "Do not follow the link."
                }],
                "scheme": "invalid",
                "domain": "invalid",
                "path": ""
            }

        scheme = (parsed.scheme or "").lower()
        netloc = (parsed.netloc or "").lower()
        path = parsed.path or ""
        query = parsed.query or ""

        # Remove port if present
        domain = netloc.split(":")[0] if ":" in netloc else netloc

        # 1. Scheme Check (HTTP vs HTTPS)
        if scheme == "http":
            indicators.append({
                "category": "URL",
                "name": "Unencrypted HTTP Protocol",
                "severity": "Medium",
                "assigned_score": 10,
                "evidence": f"URL uses http:// instead of secure https:// ({url[:80]})",
                "description": "Legitimate enterprise services enforce HTTPS. Plain HTTP links transmit data unencrypted.",
                "recommended_action": "Never input credentials or sensitive data over unencrypted HTTP."
            })
            reasons.append("Unencrypted HTTP")
            is_suspicious = True

        # 2. IP Address in Hostname (e.g., http://192.168.1.1/login)
        is_ip_host = False
        try:
            ipaddress.ip_address(domain)
            is_ip_host = True
            indicators.append({
                "category": "URL",
                "name": "Direct IP Address in URL Hostname",
                "severity": "High",
                "assigned_score": 25,
                "evidence": f"Host is raw IP: {domain}",
                "description": "Phishers use direct IP hostnames to bypass domain reputation scanners and DNS blacklists.",
                "recommended_action": "Block the IP and do not access the link."
            })
            reasons.append("Direct IP Hostname")
            is_suspicious = True
        except ValueError:
            pass

        # 3. URL Shortener Detection
        is_shortener = domain in URLAnalyzer.SHORTENER_DOMAINS or any(domain.endswith("." + s) for s in URLAnalyzer.SHORTENER_DOMAINS)
        if is_shortener:
            indicators.append({
                "category": "URL",
                "name": "URL Shortener Service Used",
                "severity": "Medium",
                "assigned_score": 15,
                "evidence": f"Shortener domain detected: {domain}",
                "description": "URL shortening services conceal the true destination of the link, commonly used to evade email gateways.",
                "recommended_action": "Expand the shortened URL in a secure sandbox before interacting."
            })
            reasons.append("Shortened URL concealing destination")
            is_suspicious = True

        # 4. Punycode / Internationalized Domain Name (Homograph Attack)
        if "xn--" in domain:
            indicators.append({
                "category": "URL",
                "name": "Punycode / Homograph Domain Detected",
                "severity": "Critical",
                "assigned_score": 30,
                "evidence": f"Punycode encoded domain: {domain}",
                "description": "Punycode (xn--) is frequently leveraged for IDN homograph attacks where Cyrillic or Greek lookalikes disguise fake brand domains.",
                "recommended_action": "Do not open link; high risk of spoofing."
            })
            reasons.append("Punycode homograph domain")
            is_suspicious = True

        # 5. Check Non-ASCII Cyrillic / Homograph Characters
        has_homograph = any(c in URLAnalyzer.HOMOGRAPH_LOOKALIKES for c in domain)
        if has_homograph:
            indicators.append({
                "category": "URL",
                "name": "Non-ASCII / Homograph Character Lookalike",
                "severity": "Critical",
                "assigned_score": 30,
                "evidence": f"Domain contains Cyrillic/homograph characters: {domain}",
                "description": "Visual spoofing detected: characters from other alphabets mimic standard Latin characters.",
                "recommended_action": "Immediate indicator of deliberate credential phishing."
            })
            reasons.append("Homograph characters detected")
            is_suspicious = True

        # 6. Typosquatting and Brand Impersonation in Domain
        for brand in URLAnalyzer.TARGET_BRANDS:
            # Check exact brand in domain parts
            domain_parts = domain.split(".")
            brand_in_domain = False
            for part in domain_parts:
                if part == brand:
                    # Brand is an exact match for a subdomain or domain; check if it's the official domain
                    if not (domain.endswith(f"{brand}.com") or domain.endswith(f"{brand}.org") or domain.endswith(f"{brand}.net")):
                        indicators.append({
                            "category": "URL",
                            "name": f"Brand Keyword in Unofficial Domain ({brand.title()})",
                            "severity": "High",
                            "assigned_score": 25,
                            "evidence": f"Domain '{domain}' includes brand '{brand}' under an unofficial TLD/structure",
                            "description": f"The domain uses the '{brand}' name to mimic official services without belonging to the official company domain.",
                            "recommended_action": "Do not navigate to this link; verify through official bookmarks."
                        })
                        reasons.append(f"Brand mimicry: {brand}")
                        is_suspicious = True
                        brand_in_domain = True
                        break
                elif brand in part and part != brand:
                    # Hyphenated or combined like paypal-verify or update-apple
                    indicators.append({
                        "category": "URL",
                        "name": f"Typosquatting / Compound Brand Subdomain ({brand.title()})",
                        "severity": "High",
                        "assigned_score": 25,
                        "evidence": f"Subdomain/token contains '{part}' mimicking '{brand}'",
                        "description": f"Domain leverages brand confusion with suspicious prefix/suffix additions.",
                        "recommended_action": "Avoid accessing; hallmark of phishing landing pages."
                    })
                    reasons.append(f"Compound brand spoof: {brand}")
                    is_suspicious = True
                    brand_in_domain = True
                    break
            if brand_in_domain:
                break

        # 7. Suspicious TLD Detection
        for tld in URLAnalyzer.SUSPICIOUS_TLDS:
            if domain.endswith(tld):
                indicators.append({
                    "category": "URL",
                    "name": "High-Risk Top-Level Domain (TLD)",
                    "severity": "Medium",
                    "assigned_score": 15,
                    "evidence": f"Domain ends with known spam/phishing TLD: {tld}",
                    "description": f"The TLD {tld} is disproportionately utilized by cheap disposable phishing campaigns.",
                    "recommended_action": "Scrutinize sender and website authenticity."
                })
                reasons.append(f"Suspicious TLD ({tld})")
                is_suspicious = True
                break

        # 8. Excessive Subdomains (e.g. login.secure.verify.account.paypal.evil.com)
        subdomain_count = len(domain.split(".")) - 2
        if subdomain_count >= 3:
            indicators.append({
                "category": "URL",
                "name": "Excessive Subdomain Stacking",
                "severity": "Medium",
                "assigned_score": 12,
                "evidence": f"Domain has {subdomain_count + 1} levels: {domain}",
                "description": "Multi-level subdomains are commonly employed to push the actual apex domain off-screen on mobile devices.",
                "recommended_action": "Examine the right-most domain segments to find the true host."
            })
            reasons.append("Excessive subdomains")
            is_suspicious = True

        # 9. HTML Anchor Text vs Href Mismatch (Crucial Phishing Indicator!)
        if anchor_text:
            anchor_clean = anchor_text.strip().lower()
            # If anchor text looks like a URL (starts with http or www or has domain)
            if "http://" in anchor_clean or "https://" in anchor_clean or "www." in anchor_clean:
                # Extract domain from anchor
                anchor_match = re.search(r"(?:https?://)?([a-z0-9.-]+\.[a-z]{2,})", anchor_clean)
                if anchor_match:
                    anchor_domain = anchor_match.group(1).lower()
                    if anchor_domain != domain and not domain.endswith("." + anchor_domain):
                        indicators.append({
                            "category": "URL",
                            "name": "Deceptive Hyperlink (Anchor Text vs Href Mismatch)",
                            "severity": "Critical",
                            "assigned_score": 35,
                            "evidence": f"Visible Text shows '{anchor_text}' but link secretly directs to '{url}'",
                            "description": "The clickable link text presents a trusted website, but clicking it silently redirects victims to a malicious site.",
                            "recommended_action": "Classic credential harvester trick. Do NOT click."
                        })
                        reasons.append("Deceptive anchor text mismatch")
                        is_suspicious = True

        # 10. Open Redirect / Suspicious Redirection Parameters in URL
        redirect_params = ["redirect", "url", "next", "link", "target", "dest", "destination", "goto", "out"]
        query_lower = query.lower()
        for param in redirect_params:
            if f"{param}=http" in query_lower or f"{param}=https" in query_lower or f"{param}=//" in query_lower:
                indicators.append({
                    "category": "URL",
                    "name": "Potential Open Redirect / URL Forwarding Parameter",
                    "severity": "High",
                    "assigned_score": 20,
                    "evidence": f"Query contains redirection parameter '{param}': {query[:100]}",
                    "description": "Open redirect patterns allow attackers to bounce victims through a trusted host to an arbitrary phishing page.",
                    "recommended_action": "Check the final destination before following the link."
                })
                reasons.append("Open redirect parameter")
                is_suspicious = True
                break

        # 11. Suspicious Path or Credential Keywords in Path/Query
        credential_keywords = ["login", "signin", "verify", "account", "update", "banking", "secure", "password", "wallet", "invoice"]
        full_path_query = (path + "?" + query).lower()
        matched_keywords = [kw for kw in credential_keywords if kw in full_path_query]
        if matched_keywords and (is_suspicious or is_shortener or is_ip_host):
            indicators.append({
                "category": "URL",
                "name": "Credential Harvesting Keywords in Path",
                "severity": "Medium",
                "assigned_score": 15,
                "evidence": f"Suspicious tokens in URL path/query: {', '.join(matched_keywords)}",
                "description": "URL targets sensitive authentication workflows on an unverified host.",
                "recommended_action": "Do not provide credentials."
            })
            reasons.append("Credential harvesting tokens")

        return {
            "url": url,
            "scheme": scheme,
            "domain": domain,
            "path": path,
            "query": query,
            "anchor_text": anchor_text,
            "is_suspicious": is_suspicious,
            "reasons": reasons,
            "indicators": indicators
        }
