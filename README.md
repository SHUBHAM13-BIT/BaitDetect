# BaitDetect // AI-Powered Phishing Email Analysis and Detection System

[![Python 3.12+](https://img.shields.io/badge/Python-3.12%2B-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Framework: Flask](https://img.shields.io/badge/Framework-Flask_3.1-black.svg)](https://palletsprojects.com/p/flask/)
[![Report Engine: ReportLab](https://img.shields.io/badge/Reporting-ReportLab_5.1-red.svg)](https://www.reportlab.com/)
[![Tests: 47 Passed](https://img.shields.io/badge/Tests-47%20Passed-brightgreen.svg)]()

BaitDetect is a professional-grade cybersecurity platform engineered for Security Operations Centers (SOC), Threat Intelligence Analysts, and enterprise email administrators. It performs deep, non-executing static inspection of suspicious emails, extracting headers, URLs, attachments, and psychological coercion markers to produce an auditable 0–100 threat score and forensic incident reports.

---

## 1. Key Capabilities & Core Modules

### 🛡️ A. Email Input Module
- **Multi-Format Ingestion:** Paste RFC 822 email source, loose headers, or body text directly, or upload `.eml`, `.txt`, `.msg`, and `.header` files.
- **Safe Extraction:** Never executes or detonates uploaded attachments; in-memory stream processing only.
- **MIME & Plaintext Normalization:** Robust parsing across multipart boundaries, encoded headers, and loose line-by-line dumps.

### 🔍 B. Header Analysis & Routing Intelligence
- **Authentication Breakdown:** Evaluates SPF, DKIM, and DMARC verification records. **Critically distinguishes between explicit authentication failures (`FAIL`) and missing security policies (`MISSING`).**
- **Envelope Discrepancies:** Detects sender and `Reply-To` mismatches (e.g. corporate sender redirecting responses to free-mail providers like Gmail).
- **Display Name Spoofing:** Identifies brand impersonation (e.g., `"PayPal Security" <attacker@evil.xyz>`).
- **Hop-by-Hop Trace:** Maps MTA routing paths across `Received` headers to isolate true sending IP addresses and private network leaks.

### 🌐 C. Passive URL Intelligence
- **Zero-Execution Inspection:** Analyzes links syntactically and against threat feeds without loading them in a browser.
- **Direct IP Hostnames:** Flags raw IP URLs (e.g. `http://198.51.100.45/login`).
- **URL Shorteners:** Detects redirection masking (bit.ly, tinyurl, t.co, is.gd, etc.).
- **IDN Homographs & Punycode:** Flags Cyrillic/Greek lookalike substitution attacks (`xn--`).
- **Anchor Text vs. Href Mismatches:** Detects deceptive links where visible text shows a trusted brand (`https://paypal.com`) while the hyperlink directs to an attacker server.
- **Typosquatting Detection:** Pattern matches against 20+ prominent enterprise brands.
- **Threat Intelligence:** Direct querying of the abuse.ch URLhaus malware database.

### 📎 D. Safe Attachment Analysis
- **In-Memory Cryptographic Fingerprinting:** Computes SHA-256 hashes without saving binaries to disk.
- **Double Extension Disguise:** Flags camouflage tactics such as `invoice.pdf.exe` or `statement.xlsx.vbs`.
- **Executable & Script Blockers:** Identifies `.exe`, `.scr`, `.vbs`, `.js`, `.bat`, `.cmd`, `.hta`, `.ps1`.
- **Dangerous Office Formats:** Flags macro-enabled documents (`.docm`, `.xlsm`).
- **Disk Image Containers:** Detects `.iso`, `.img`, `.vhd` formats used to evade Mark-of-the-Web (MOTW).

### 🧠 E. Rule-Based Content & Psychological Heuristics
- **Social Engineering Triggers:** Detects artificial urgency, account deactivation deadlines ("within 24 hours"), and coercive threats.
- **Credential Harvesting Patterns:** Flags login verification links, unauthorized activity alerts, and password reset traps.
- **Business Email Compromise (BEC):** Flags executive impersonation ("are you at your desk?", urgent wire transfer requests, secret vendor payments).
- **Advance Fee & Financial Scams:** Identifies lottery winnings, crypto transactions, and overdue fake invoices.
- **Scientific Transparency:** Features a clear heuristic disclaimer stating behavioral detection provides probabilistic threat indicators, not definitive mathematical proof.

### 📊 F. Risk Scoring Engine (0–100 Scale)
Evaluates indicators across Header, URL, Attachment, Content, and Threat Intelligence vectors:
- **0 – 20: Safe / Low Risk** (Benign legitimate email)
- **21 – 40: Moderate Risk** (Unsolicited promotional / missing optional records)
- **41 – 60: Suspicious** (Mismatched headers, shorteners, urgency language)
- **61 – 80: High Risk** (Spoofed display names, credential harvesting lures)
- **81 – 100: Critical Risk** (Potential phishing, executable disguise, DMARC failure)

**Deduplication & Category Caps:** Normalizes related indicators to eliminate double-counting, backed by a **Critical Override Rule** that elevates multi-critical alerts to 85+ score.

### 📑 G. Audit-Ready Incident Reporting
- **ReportLab PDF Generator:** Audit-ready cybersecurity incident investigation report with executive summary, metadata grid, SPF/DKIM/DMARC table, detected indicators breakdown, and SOC remediation steps.
- **JSON Export:** Structured JSON schema for SIEM/SOAR ingestion.
- **CSV Export:** Aggregated threat ledger for audit compliance.

---

## 2. Technology Stack

- **Backend:** Python 3.12+, Flask 3.1, Werkzeug, dnspython, Requests
- **Frontend:** HTML5, CSS3, JavaScript (ES6+), Bootstrap 5, Bootstrap Icons, Chart.js 4.4
- **Database:** SQLite 3 (WAL mode, parameterized queries)
- **PDF Engine:** ReportLab 5.1 with custom canvas page numbering
- **Testing:** Pytest 9.2 (47 automated tests)

---

## 3. Project Structure

```
BaitDetect/
├── app.py                      # Flask Application entry point & REST APIs
├── config.py                   # Central configuration & directory loader
├── requirements.txt            # Python dependencies
├── .env.example                # Environment variable template
├── .env                        # Local configuration
├── .gitignore                  # Git ignore rules
├── verify_system.py            # Standalone end-to-end verification script
│
├── analyzer/                   # Core Security Analysis Engines
│   ├── __init__.py
│   ├── email_parser.py         # RFC 822 & MIME parser, in-memory SHA-256
│   ├── header_analyzer.py      # SPF/DKIM/DMARC, spoofing & hop analysis
│   ├── url_analyzer.py         # Passive link forensics, homographs, typosquatting
│   ├── attachment_analyzer.py  # Double extensions, executables, macro detection
│   ├── content_analyzer.py     # Psychological & behavioral phishing heuristics
│   ├── threat_intelligence.py  # URLhaus, VirusTotal hooks & live DNS TXT
│   ├── risk_engine.py          # 0-100 composite scoring & category capping
│   └── pipeline.py             # Master analysis orchestrator
│
├── database/                   # SQLite Storage
│   └── database.py             # Schema, migrations, CRUD, and metrics
│
├── reports/                    # Incident Report Generation
│   └── report_generator.py     # ReportLab PDF, JSON, and CSV exporters
│
├── templates/                  # Frontend HTML Templates (All 10 Sections)
│   ├── base.html               # Master layout with sidebar & notifications
│   ├── index.html              # Section 1: Operations Overview & KPI Dashboard
│   ├── analyze.html            # Section 2: Email Analysis & Ingestion Module
│   ├── section_headers.html    # Section 3: Header Analysis & Routing Path
│   ├── section_urls.html       # Section 4: URL Intelligence & Domain Forensics
│   ├── section_attachments.html# Section 5: Attachment Security Audit
│   ├── section_indicators.html # Section 6: Threat Indicators Catalog
│   ├── section_risk.html       # Section 7: Risk Assessment Framework
│   ├── history.html            # Section 8: Analysis History & Audit Log
│   ├── reports.html            # Section 9: Incident Reports & Exports
│   └── settings.html           # Section 10: System Configuration & API Keys
│
├── static/                     # Static Frontend Assets
│   ├── css/
│   │   └── cybersecurity.css   # Dark cybersecurity theme stylesheet
│   └── js/
│       └── dashboard.js        # Dynamic UI, Chart.js integrations & samples
│
├── tests/                      # Automated Verification & Test Suite
│   ├── test_email_parser.py
│   ├── test_header_analyzer.py
│   ├── test_url_analyzer.py
│   ├── test_attachment_analyzer.py
│   ├── test_risk_engine.py
│   ├── test_scenarios.py       # All 15 mandatory test scenarios
│   └── test_application.py     # Flask routes, API, and export tests
│
├── uploads/                    # Temporary upload storage (.gitkeep)
└── generated_reports/          # Generated PDF, JSON, and CSV reports
```

---

## 4. Installation & Setup (Windows 11)

### Prerequisites
- Python 3.12+ installed (verify with `python --version`)
- PowerShell or Windows Command Prompt

### Step 1: Clone or Navigate to Directory
```powershell
cd "c:\Users\Shubham Chaudhary\Downloads\BaitDetect"
```

### Step 2: Create and Activate Virtual Environment
```powershell
python -m venv venv
.\venv\Scripts\Activate.ps1
```

### Step 3: Install Dependencies
```powershell
pip install -r requirements.txt
```

### Step 4: Configure Environment Variables
Copy `.env.example` to `.env` (already done by default):
```powershell
Copy-Item .env.example .env
```

---

## 5. Running the Application

Start the web application:
```powershell
.\venv\Scripts\python.exe app.py
```

The system will start and be accessible at:
👉 **http://127.0.0.1:5000**

---

## 6. How to Use the System

### A. Analyzing an Email
1. Open the dashboard at `http://127.0.0.1:5000`.
2. Navigate to **2. Email Analysis** or use the quick scanner on the **Overview** page.
3. Paste raw email source or upload a `.eml` / `.txt` file.
   * *Tip:* Click any of the **Synthetic Test Samples** buttons (**Credential Phish**, **BEC Fraud**, **Malware Invoice**, **Legitimate**) to immediately load realistic scenarios.
4. Click **Run Comprehensive Threat Analysis**.
5. Inspect the deep-dive report showing risk gauge, header hops, extracted URLs, attachment hashes, and indicator breakdown.

### B. Exporting Reports
- Click **Download PDF Report** to view or print the incident PDF.
- Click **Export JSON** for SIEM/SOAR ingestion.
- Navigate to **9. Reports & Exports** or **8. Analysis History** to download the aggregate CSV summary.

### C. Using the REST API
Submit an email programmatically via curl or Python:
```bash
curl -X POST http://127.0.0.1:5000/api/v1/analyze \
     -H "Content-Type: application/json" \
     -d '{"raw_content": "From: billing@fake.xyz\nSubject: Invoice\n\nClick: http://198.51.100.1/pay"}'
```

---

## 7. Running the Automated Test Suite

Run all 47 unit, functional, scenario, and security tests:
```powershell
.\venv\Scripts\pytest.exe -v
```

Run the standalone end-to-end verification script:
```powershell
.\venv\Scripts\python.exe verify_system.py
```

### Mandatory Scenarios Verified:
| # | Scenario | Detection Result |
|---|---|---|
| 1 | Normal Legitimate Email | Risk Score: 20/100 (Safe) |
| 2 | Suspicious Sender Address | Flagged: Display name spoofing & suspicious TLD |
| 3 | Fake Password Reset Email | Risk Score: 70+/100 (High Risk), Credential Harvesting |
| 4 | Suspicious URL | Flagged: Unofficial domain, direct IP host |
| 5 | URL Shortener | Flagged: Obfuscated destination via shortener |
| 6 | Sender & Reply-To Mismatch | Flagged: Free-mail redirect diversion |
| 7 | Missing SPF Information | Flagged: Missing policy (distinguished from failure) |
| 8 | Failed DKIM Authentication | Flagged: Cryptographic signature mismatch |
| 9 | Suspicious Attachment Filename | Flagged: Double extension disguise (`.pdf.exe`) |
| 10 | Empty Email Input | Handled: Graceful validation error |
| 11 | Invalid Uploaded File | Handled: File extension and content validation |
| 12 | Corrupted EML File | Handled: Fallback line-by-line parsing |
| 13 | Large Email Content (100k+ chars) | Handled: Non-blocking memory streaming |
| 14 | API Unavailable (VirusTotal) | Handled: Graceful fallback to local heuristics |
| 15 | Network Unavailable (DNS Timeout) | Handled: Non-blocking DNS timeout with offline markers |

---

## 8. Security Controls & Architecture

- **Zero Detonation Policy:** No link is visited by an automated browser; no attachment payload is written to disk with execution permissions or executed.
- **Upload Hardening:** Restricted strictly to `.eml`, `.txt`, `.msg`, and `.header` with filename sanitization.
- **SQL Injection Defense:** All queries utilize SQLite parameterization (`?` placeholders).
- **Path Traversal Protection:** User inputs and IDs are sanitized via `secure_filename()` before filesystem access.

---

## 9. Project Limitations & Future Scope

### Limitations
- Dynamic JavaScript-rendered links in HTML bodies that require full DOM evaluation are parsed statically via regex and HTML tokenization.
- Live VirusTotal scanning requires an active user-provided API key in Settings (URLhaus is enabled without keys).

### Future Improvements
- Integration with local sandbox environments (Cuckoo / CAPE sandbox) for isolated attachment detonation.
- Fine-tuned transformer model (e.g. RoBERTa/DeBERTa) for multilingual spear-phishing detection.
- IMAP/POP3 live mailbox listener for automated continuous threat ingestion.
