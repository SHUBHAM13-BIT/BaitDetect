import re
import email
from email import policy
from email.parser import BytesParser, Parser
from email.utils import parseaddr
import hashlib
from html.parser import HTMLParser
from typing import Dict, List, Any, Optional

class SimpleHTMLLinkExtractor(HTMLParser):
    """Safely extracts links and text from HTML body without external heavy dependencies."""
    def __init__(self):
        super().__init__()
        self.links: List[Dict[str, str]] = []
        self._current_href: Optional[str] = None
        self._current_text: List[str] = []
        self.text_content: List[str] = []

    def handle_starttag(self, tag, attrs):
        if tag.lower() == "a":
            for attr, val in attrs:
                if attr.lower() == "href" and val:
                    self._current_href = val.strip()
                    self._current_text = []

    def handle_endtag(self, tag):
        if tag.lower() == "a" and self._current_href:
            anchor_text = "".join(self._current_text).strip()
            self.links.append({
                "href": self._current_href,
                "text": anchor_text
            })
            self._current_href = None
            self._current_text = []

    def handle_data(self, data):
        clean_data = data.strip()
        if clean_data:
            self.text_content.append(clean_data)
        if self._current_href is not None:
            self._current_text.append(data)

def extract_email_address_and_domain(raw_header: str) -> Dict[str, str]:
    """Parse address header (e.g. 'John Doe <jdoe@company.com>') into parts."""
    if not raw_header:
        return {"display_name": "", "address": "", "domain": ""}
    display_name, address = parseaddr(raw_header)
    address = address.strip().lower()
    domain = address.split("@")[-1] if "@" in address else ""
    return {
        "display_name": display_name.strip(),
        "address": address,
        "domain": domain
    }

class EmailParser:
    """Robust, secure email parser for raw strings, .eml bytes, or loose headers."""

    @staticmethod
    def parse(raw_content: Any) -> Dict[str, Any]:
        """
        Parses raw email input (str, bytes) into structured format.
        Never executes attachments. Calculates hashes securely in memory.
        """
        errors = []
        if raw_content is None:
            return {"is_valid": False, "errors": ["Empty input provided."]}

        if isinstance(raw_content, str):
            raw_bytes = raw_content.encode("utf-8", errors="replace")
            raw_str = raw_content
        elif isinstance(raw_content, bytes):
            raw_bytes = raw_content
            raw_str = raw_content.decode("utf-8", errors="replace")
        else:
            return {"is_valid": False, "errors": ["Unsupported content type for email parsing."]}

        if not raw_str.strip():
            return {"is_valid": False, "errors": ["Email content is blank."]}

        msg = None
        try:
            # Use BytesParser with modern default policy
            msg = BytesParser(policy=policy.default).parsebytes(raw_bytes)
        except Exception as e:
            errors.append(f"MIME parser warning: {str(e)}")
            try:
                msg = email.message_from_string(raw_str)
            except Exception as e2:
                errors.append(f"Legacy parser error: {str(e2)}")

        # If MIME parsing yielded no headers or basic headers, attempt loose header parsing fallback
        headers: Dict[str, Any] = {}
        received_headers: List[str] = []
        raw_headers_text = ""

        if msg is not None:
            # Collect all headers
            for k, v in msg.items():
                k_lower = k.lower()
                v_str = str(v)
                if k_lower == "received":
                    received_headers.append(v_str)
                else:
                    # Keep first or concatenate
                    if k_lower in headers:
                        if isinstance(headers[k_lower], list):
                            headers[k_lower].append(v_str)
                        else:
                            headers[k_lower] = [headers[k_lower], v_str]
                    else:
                        headers[k_lower] = v_str

        # If headers are sparse (e.g. user pasted only headers or plain text with From: ...),
        # parse line-by-line fallback
        if not headers.get("from") and not headers.get("subject") and not received_headers:
            loose_headers, loose_body = EmailParser._parse_loose_text(raw_str)
            if loose_headers:
                headers = loose_headers
                if "received" in headers and isinstance(headers["received"], list):
                    received_headers = headers["received"]

        # Reconstruct header text
        if msg is not None and hasattr(msg, "_headers") and msg._headers:
            raw_headers_text = "\n".join(f"{k}: {v}" for k, v in msg._headers)
        else:
            raw_headers_text = "\n".join(f"{k}: {v}" for k, v in headers.items())

        # Extract Standard Fields
        from_header = EmailParser._get_header(headers, "from")
        reply_to_header = EmailParser._get_header(headers, "reply-to")
        return_path_header = EmailParser._get_header(headers, "return-path")
        subject = EmailParser._get_header(headers, "subject")
        date_header = EmailParser._get_header(headers, "date")
        message_id = EmailParser._get_header(headers, "message-id")
        auth_results = EmailParser._get_header(headers, "authentication-results")
        delivered_to = EmailParser._get_header(headers, "delivered-to")
        x_mailer = EmailParser._get_header(headers, "x-mailer") or EmailParser._get_header(headers, "user-agent")

        sender_info = extract_email_address_and_domain(from_header)
        reply_to_info = extract_email_address_and_domain(reply_to_header)
        return_path_info = extract_email_address_and_domain(return_path_header)

        # Extract Body and Attachments
        body_plain_parts = []
        body_html_parts = []
        attachments = []

        if msg is not None:
            try:
                for part in msg.walk():
                    content_disposition = str(part.get("Content-Disposition", ""))
                    content_type = part.get_content_type()
                    filename = part.get_filename()

                    is_attachment = ("attachment" in content_disposition.lower()) or bool(filename)

                    if is_attachment:
                        # Extract attachment safely (in-memory only, no disk execution)
                        fname = filename or "unnamed_attachment"
                        payload = part.get_payload(decode=True) or b""
                        sha256_hash = hashlib.sha256(payload).hexdigest() if payload else ""
                        size_bytes = len(payload)

                        attachments.append({
                            "filename": fname,
                            "content_type": content_type,
                            "size_bytes": size_bytes,
                            "sha256": sha256_hash,
                            "is_inline": "inline" in content_disposition.lower()
                        })
                    else:
                        if content_type == "text/plain":
                            try:
                                payload = part.get_payload(decode=True)
                                if payload:
                                    body_plain_parts.append(payload.decode("utf-8", errors="replace"))
                            except Exception:
                                pass
                        elif content_type == "text/html":
                            try:
                                payload = part.get_payload(decode=True)
                                if payload:
                                    body_html_parts.append(payload.decode("utf-8", errors="replace"))
                            except Exception:
                                pass
            except Exception as e:
                errors.append(f"MIME part walk error: {str(e)}")

        body_plain = "\n".join(body_plain_parts).strip()
        body_html = "\n".join(body_html_parts).strip()

        # If body is still empty, check if entire raw_str can be body
        if not body_plain and not body_html:
            # Check if there was loose text after header block
            _, loose_body = EmailParser._parse_loose_text(raw_str)
            body_plain = loose_body if loose_body else raw_str

        # Extract HTML links if HTML present
        html_links = []
        if body_html:
            link_extractor = SimpleHTMLLinkExtractor()
            try:
                link_extractor.feed(body_html)
                html_links = link_extractor.links
                if not body_plain and link_extractor.text_content:
                    body_plain = " ".join(link_extractor.text_content)
            except Exception as e:
                errors.append(f"HTML link parsing error: {str(e)}")

        return {
            "is_valid": True,
            "errors": errors,
            "subject": subject or "(No Subject)",
            "date": date_header or "",
            "message_id": message_id or "",
            "from_raw": from_header,
            "sender_info": sender_info,
            "reply_to_raw": reply_to_header,
            "reply_to_info": reply_to_info,
            "return_path_raw": return_path_header,
            "return_path_info": return_path_info,
            "delivered_to": delivered_to,
            "x_mailer": x_mailer,
            "authentication_results": auth_results,
            "received_headers": received_headers,
            "headers": headers,
            "raw_headers": raw_headers_text,
            "body_plain": body_plain,
            "body_html": body_html,
            "html_links": html_links,
            "attachments": attachments,
            "has_attachments": len(attachments) > 0,
            "raw_content_preview": raw_str[:1000]
        }

    @staticmethod
    def _get_header(headers: Dict[str, Any], key: str) -> str:
        val = headers.get(key.lower(), "")
        if isinstance(val, list):
            return val[0] if val else ""
        return str(val)

    @staticmethod
    def _parse_loose_text(raw_text: str):
        """Parse headers from loose text lines until an empty line separates headers and body."""
        lines = raw_text.splitlines()
        headers: Dict[str, Any] = {}
        body_lines = []
        in_headers = True
        current_key = None

        header_regex = re.compile(r"^([A-Za-z0-9_-]+)\s*:\s*(.*)$")

        for line in lines:
            if in_headers:
                if not line.strip():
                    in_headers = False
                    continue
                match = header_regex.match(line)
                if match:
                    current_key = match.group(1).lower()
                    val = match.group(2).strip()
                    if current_key == "received":
                        headers.setdefault("received", []).append(val)
                    else:
                        headers[current_key] = val
                elif current_key and (line.startswith(" ") or line.startswith("\t")):
                    # Continuation of previous header
                    if current_key == "received" and headers.get("received"):
                        headers["received"][-1] += " " + line.strip()
                    else:
                        headers[current_key] = str(headers.get(current_key, "")) + " " + line.strip()
                else:
                    # Line does not match header syntax and not indentation -> switch to body
                    in_headers = False
                    body_lines.append(line)
            else:
                body_lines.append(line)

        return headers, "\n".join(body_lines).strip()
