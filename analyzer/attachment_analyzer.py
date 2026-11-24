import os
import re
from typing import Dict, List, Any

class AttachmentAnalyzer:
    """Analyzes email attachment metadata for high-risk extensions, double extensions, macros, and obfuscation."""

    # High risk executable and script extensions
    HIGH_RISK_EXECUTABLES = {
        ".exe", ".scr", ".vbs", ".vbe", ".js", ".jse", ".bat", ".cmd", ".hta",
        ".ps1", ".ps2", ".wsf", ".wsh", ".msc", ".cpl", ".pif", ".gadget",
        ".jar", ".com", ".reg", ".dll", ".sys", ".inf"
    }

    # Container and disk image formats often used to bypass email gateway filters
    DISK_IMAGE_CONTAINERS = {
        ".iso", ".img", ".vhd", ".vhdx", ".dmg"
    }

    # Macro-enabled Office extensions
    MACRO_ENABLED_EXTENSIONS = {
        ".docm", ".xlsm", ".pptm", ".dotm", ".xltm", ".xlam", ".potm", ".ppam"
    }

    # Common archive formats that can encapsulate malware
    ARCHIVE_EXTENSIONS = {
        ".zip", ".rar", ".7z", ".tar", ".gz", ".bz2", ".xz", ".iso", ".cab", ".ace"
    }

    # Suspicious lure keywords in filenames
    SUSPICIOUS_NAME_KEYWORDS = [
        "invoice", "payment", "receipt", "remittance", "wire", "transfer",
        "swift", "overdue", "purchase", "order", "statement", "salary",
        "confidential", "urgent", "rfq", "po_", "doc0", "scan", "tax", "w2"
    ]

    @staticmethod
    def analyze(attachments_list: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Evaluates attachment metadata.
        Never executes or saves payload files to disk.
        """
        analyzed_attachments = []
        indicators = []
        suspicious_count = 0

        for att in attachments_list:
            result = AttachmentAnalyzer._inspect_single_attachment(att)
            analyzed_attachments.append(result)

            if result["is_suspicious"]:
                suspicious_count += 1

            for ind in result["indicators"]:
                indicators.append(ind)

        return {
            "total_attachments": len(analyzed_attachments),
            "suspicious_attachments_count": suspicious_count,
            "attachments": analyzed_attachments,
            "indicators": indicators
        }

    @staticmethod
    def _inspect_single_attachment(att: Dict[str, Any]) -> Dict[str, Any]:
        filename = att.get("filename", "unnamed").strip()
        content_type = att.get("content_type", "").lower()
        size_bytes = att.get("size_bytes", 0)
        sha256 = att.get("sha256", "")
        is_inline = att.get("is_inline", False)

        indicators = []
        reasons = []
        is_suspicious = False

        # Extract file extensions
        # Check for double extensions (e.g., invoice.pdf.exe or report.docx.vbs)
        parts = filename.split(".")
        extensions = ["." + p.lower() for p in parts[1:]] if len(parts) > 1 else []
        final_ext = extensions[-1] if extensions else ""

        # 1. Double Extension Detection (Classic malware obfuscation)
        if len(extensions) >= 2:
            second_last_ext = extensions[-2]
            # If penultimate extension is innocent (pdf, doc, xls, jpg, png, txt) and final is executable or script
            innocent_decoys = {".pdf", ".doc", ".docx", ".xls", ".xlsx", ".jpg", ".png", ".txt", ".mp4"}
            if second_last_ext in innocent_decoys and (final_ext in AttachmentAnalyzer.HIGH_RISK_EXECUTABLES or final_ext in AttachmentAnalyzer.DISK_IMAGE_CONTAINERS):
                indicators.append({
                    "category": "Attachment",
                    "name": "Deceptive Double Extension Disguise",
                    "severity": "Critical",
                    "assigned_score": 35,
                    "evidence": f"Filename '{filename}' disguises '{final_ext}' behind '{second_last_ext}'",
                    "description": "Double extensions exploit default Windows settings that hide known extensions, tricking users into executing code.",
                    "recommended_action": "Do NOT execute. Block attachment immediately at email gateway."
                })
                reasons.append("Deceptive double extension disguise")
                is_suspicious = True

        # 2. Executable / Script Files
        if final_ext in AttachmentAnalyzer.HIGH_RISK_EXECUTABLES:
            indicators.append({
                "category": "Attachment",
                "name": f"High-Risk Executable Attachment ({final_ext})",
                "severity": "Critical",
                "assigned_score": 35,
                "evidence": f"Attachment has direct executable extension: {filename}",
                "description": f"Executable files ({final_ext}) should never be delivered via email and represent imminent malware threats.",
                "recommended_action": "Quarantine file immediately and submit SHA-256 hash to SOC sandbox."
            })
            reasons.append(f"Direct executable file ({final_ext})")
            is_suspicious = True

        # 3. Disk Image Container (.iso, .img, .vhd)
        if final_ext in AttachmentAnalyzer.DISK_IMAGE_CONTAINERS:
            indicators.append({
                "category": "Attachment",
                "name": f"Disk Image Container Attachment ({final_ext})",
                "severity": "High",
                "assigned_score": 25,
                "evidence": f"Attachment is a virtual disk image container: {filename}",
                "description": "Attackers package malware in ISO/VHD images to bypass email gateway MOTW (Mark-of-the-Web) inspection.",
                "recommended_action": "Do not mount disk image. Scan with endpoint security."
            })
            reasons.append(f"Disk image container ({final_ext})")
            is_suspicious = True

        # 4. Macro-Enabled Office Documents
        if final_ext in AttachmentAnalyzer.MACRO_ENABLED_EXTENSIONS:
            indicators.append({
                "category": "Attachment",
                "name": f"Macro-Enabled Office Document ({final_ext})",
                "severity": "High",
                "assigned_score": 25,
                "evidence": f"Attachment is macro-enabled: {filename}",
                "description": "Macro-enabled documents (.docm, .xlsm) frequently run automated VBA payload downloaders upon opening.",
                "recommended_action": "Disable macros before viewing; verify necessity of macro execution with sender."
            })
            reasons.append(f"Macro-enabled document ({final_ext})")
            is_suspicious = True

        # 5. Archive Files (.zip, .7z, .rar) with Suspicious Financial/Urgent Lure Names
        if final_ext in AttachmentAnalyzer.ARCHIVE_EXTENSIONS:
            filename_lower = filename.lower()
            matched_keywords = [kw for kw in AttachmentAnalyzer.SUSPICIOUS_NAME_KEYWORDS if kw in filename_lower]
            if matched_keywords:
                indicators.append({
                    "category": "Attachment",
                    "name": "Compressed Archive with Financial/Urgency Lure",
                    "severity": "Medium",
                    "assigned_score": 15,
                    "evidence": f"Archive '{filename}' contains lure keywords: {', '.join(matched_keywords)}",
                    "description": "Compressed archives with financial/urgent titles are standard delivery vehicles for info-stealers and trojans.",
                    "recommended_action": "Inspect archive contents safely inside isolated sandbox."
                })
                reasons.append("Archive with financial lure name")
                is_suspicious = True
            else:
                indicators.append({
                    "category": "Attachment",
                    "name": "Compressed Archive Attachment",
                    "severity": "Low",
                    "assigned_score": 5,
                    "evidence": f"Archive attachment: {filename}",
                    "description": "Archives can hide malicious payloads from standard signature scanners.",
                    "recommended_action": "Scan extracted contents before executing."
                })

        # 6. Right-to-Left Override (RLO) or Whitespace Padding
        if "\u202e" in filename or re.search(r"\s{4,}", filename):
            indicators.append({
                "category": "Attachment",
                "name": "Filename Obfuscation (RLO or Excessive Whitespace)",
                "severity": "Critical",
                "assigned_score": 35,
                "evidence": f"Obfuscated filename pattern detected in '{filename}'",
                "description": "Attackers insert Unicode Right-to-Left Override (U+202E) or long spaces to hide the real executable extension.",
                "recommended_action": "Definite malicious payload attempt. Delete immediately."
            })
            reasons.append("Filename obfuscation (RLO/Whitespace)")
            is_suspicious = True

        # 7. MIME Type Mismatch (e.g. content_type claims application/pdf but extension is .exe)
        if "pdf" in content_type and final_ext != ".pdf":
            indicators.append({
                "category": "Attachment",
                "name": "MIME Content-Type Discrepancy",
                "severity": "Medium",
                "assigned_score": 15,
                "evidence": f"MIME header '{content_type}' conflicts with extension '{final_ext}'",
                "description": "Mismatched MIME type indicates potential header tampering to bypass extension filters.",
                "recommended_action": "Inspect file signature (magic bytes) in isolated sandbox."
            })
            reasons.append("MIME type mismatch")
            is_suspicious = True

        return {
            "filename": filename,
            "extension": final_ext,
            "all_extensions": extensions,
            "content_type": content_type,
            "size_bytes": size_bytes,
            "size_formatted": AttachmentAnalyzer._format_bytes(size_bytes),
            "sha256": sha256,
            "is_inline": is_inline,
            "is_suspicious": is_suspicious,
            "reasons": reasons,
            "indicators": indicators
        }

    @staticmethod
    def _format_bytes(size: int) -> str:
        for unit in ['B', 'KB', 'MB', 'GB']:
            if size < 1024.0:
                return f"{size:.1f} {unit}"
            size /= 1024.0
        return f"{size:.1f} TB"
