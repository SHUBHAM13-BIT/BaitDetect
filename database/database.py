import sqlite3
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Any
from config import Config

def get_db_connection():
    conn = sqlite3.connect(Config.DATABASE_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db_connection()
    cursor = conn.cursor()

    # Analyses Table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS analyses (
        id TEXT PRIMARY KEY,
        created_at TEXT NOT NULL,
        sender TEXT,
        sender_display_name TEXT,
        sender_domain TEXT,
        reply_to TEXT,
        return_path TEXT,
        subject TEXT,
        date_header TEXT,
        message_id TEXT,
        sending_ip TEXT,
        routing_hops INTEGER DEFAULT 0,
        routing_summary TEXT,
        body_preview TEXT,
        spf_status TEXT,
        dkim_status TEXT,
        dmarc_status TEXT,
        auth_summary TEXT,
        url_count INTEGER DEFAULT 0,
        suspicious_url_count INTEGER DEFAULT 0,
        urls_json TEXT,
        attachment_count INTEGER DEFAULT 0,
        suspicious_attachment_count INTEGER DEFAULT 0,
        attachments_json TEXT,
        content_indicators_json TEXT,
        total_indicators_count INTEGER DEFAULT 0,
        risk_score INTEGER NOT NULL,
        risk_level TEXT NOT NULL,
        threat_category TEXT,
        summary_notes TEXT,
        pdf_report_path TEXT,
        raw_email_preview TEXT,
        category_breakdown_json TEXT
    )
    """)

    # Threat Indicators Table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS threat_indicators (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        analysis_id TEXT NOT NULL,
        category TEXT NOT NULL,
        name TEXT NOT NULL,
        severity TEXT NOT NULL,
        assigned_score INTEGER NOT NULL,
        evidence TEXT,
        description TEXT,
        recommended_action TEXT,
        FOREIGN KEY (analysis_id) REFERENCES analyses (id) ON DELETE CASCADE
    )
    """)

    try:
        cursor.execute("""
            ALTER TABLE analyses ADD COLUMN category_breakdown_json TEXT
        """)
    except sqlite3.OperationalError:
        pass # Column already exists

    # Settings Table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS settings (
        key TEXT PRIMARY KEY,
        value TEXT NOT NULL,
        updated_at TEXT NOT NULL
    )
    """)

    # Pre-populate default settings if not exists
    cursor.execute("SELECT key FROM settings WHERE key = 'virustotal_api_key'")
    if not cursor.fetchone():
        now = datetime.now(timezone.utc).isoformat()
        cursor.executemany("""
            INSERT OR IGNORE INTO settings (key, value, updated_at) VALUES (?, ?, ?)
        """, [
            ("virustotal_api_key", Config.VIRUSTOTAL_API_KEY, now),
            ("google_safe_browsing_api_key", Config.GOOGLE_SAFE_BROWSING_API_KEY, now),
            ("enable_live_dns", "true", now),
            ("enable_threat_intel", "true", now),
            ("strict_mode", "false", now),
        ])

    conn.commit()
    conn.close()

def save_analysis(analysis_data: Dict[str, Any]) -> str:
    """Save full analysis and related indicators to SQLite database."""
    conn = get_db_connection()
    cursor = conn.cursor()

    analysis_id = analysis_data["id"]
    created_at = analysis_data.get("created_at") or datetime.now(timezone.utc).isoformat()

    cursor.execute("""
        INSERT INTO analyses (
            id, created_at, sender, sender_display_name, sender_domain,
            reply_to, return_path, subject, date_header, message_id,
            sending_ip, routing_hops, routing_summary, body_preview,
            spf_status, dkim_status, dmarc_status, auth_summary,
            url_count, suspicious_url_count, urls_json,
            attachment_count, suspicious_attachment_count, attachments_json,
            content_indicators_json, total_indicators_count,
            risk_score, risk_level, threat_category, summary_notes,
            pdf_report_path, raw_email_preview, category_breakdown_json
        ) VALUES (
            ?, ?, ?, ?, ?,
            ?, ?, ?, ?, ?,
            ?, ?, ?, ?,
            ?, ?, ?, ?,
            ?, ?, ?,
            ?, ?, ?,
            ?, ?,
            ?, ?, ?, ?,
            ?, ?, ?
        )
    """, (
        analysis_id,
        created_at,
        analysis_data.get("sender", ""),
        analysis_data.get("sender_display_name", ""),
        analysis_data.get("sender_domain", ""),
        analysis_data.get("reply_to", ""),
        analysis_data.get("return_path", ""),
        analysis_data.get("subject", ""),
        analysis_data.get("date_header", ""),
        analysis_data.get("message_id", ""),
        analysis_data.get("sending_ip", ""),
        analysis_data.get("routing_hops", 0),
        json.dumps(analysis_data.get("routing_summary", [])),
        analysis_data.get("body_preview", "")[:500],
        analysis_data.get("spf_status", "missing"),
        analysis_data.get("dkim_status", "missing"),
        analysis_data.get("dmarc_status", "missing"),
        json.dumps(analysis_data.get("auth_summary", {})),
        analysis_data.get("url_count", 0),
        analysis_data.get("suspicious_url_count", 0),
        json.dumps(analysis_data.get("urls", [])),
        analysis_data.get("attachment_count", 0),
        analysis_data.get("suspicious_attachment_count", 0),
        json.dumps(analysis_data.get("attachments", [])),
        json.dumps(analysis_data.get("content_indicators", [])),
        analysis_data.get("total_indicators_count", len(analysis_data.get("indicators", []))),
        analysis_data.get("risk_score", 0),
        analysis_data.get("risk_level", "Safe"),
        analysis_data.get("threat_category", "Standard Email"),
        analysis_data.get("summary_notes", ""),
        analysis_data.get("pdf_report_path", ""),
        analysis_data.get("raw_email_preview", "")[:1000],
        json.dumps(analysis_data.get("category_breakdown", {}))
    ))

    # Insert indicators
    for ind in analysis_data.get("indicators", []):
        cursor.execute("""
            INSERT INTO threat_indicators (
                analysis_id, category, name, severity, assigned_score,
                evidence, description, recommended_action
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            analysis_id,
            ind.get("category", "General"),
            ind.get("name", "Unknown Indicator"),
            ind.get("severity", "Low"),
            ind.get("assigned_score", 0),
            ind.get("evidence", ""),
            ind.get("description", ""),
            ind.get("recommended_action", "")
        ))

    conn.commit()
    conn.close()
    return analysis_id

def get_analysis_by_id(analysis_id: str) -> Optional[Dict[str, Any]]:
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM analyses WHERE id = ?", (analysis_id,))
    row = cursor.fetchone()
    if not row:
        conn.close()
        return None

    data = dict(row)
    # Parse JSON fields
    for json_field in ["routing_summary", "auth_summary", "urls_json", "attachments_json", "content_indicators_json", "category_breakdown_json"]:
        if data.get(json_field):
            try:
                data[json_field] = json.loads(data[json_field])
            except Exception:
                data[json_field] = [] if "breakdown" not in json_field else {}

    # Map back to readable keys
    data["urls"] = data.pop("urls_json", [])
    data["attachments"] = data.pop("attachments_json", [])
    data["content_indicators"] = data.pop("content_indicators_json", [])
    data["category_breakdown"] = data.pop("category_breakdown_json", {})
    if not isinstance(data.get("category_breakdown"), dict):
        data["category_breakdown"] = {"header": 0, "url": 0, "attachment": 0, "content": 0, "threat_intel": 0}

    # Fetch indicators
    cursor.execute("SELECT * FROM threat_indicators WHERE analysis_id = ? ORDER BY assigned_score DESC", (analysis_id,))
    indicators = [dict(r) for r in cursor.fetchall()]
    data["indicators"] = indicators

    conn.close()
    return data

def get_recent_analyses(limit: int = 50) -> List[Dict[str, Any]]:
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT id, created_at, sender, subject, risk_score, risk_level, threat_category,
               url_count, suspicious_url_count, attachment_count, suspicious_attachment_count,
               total_indicators_count
        FROM analyses
        ORDER BY datetime(created_at) DESC
        LIMIT ?
    """, (limit,))
    rows = [dict(r) for r in cursor.fetchall()]
    conn.close()
    return rows

def get_dashboard_statistics() -> Dict[str, Any]:
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT COUNT(*) as total FROM analyses")
    total = cursor.fetchone()["total"]

    cursor.execute("SELECT COUNT(*) as cnt FROM analyses WHERE risk_level IN ('Critical – Potential Phishing', 'High Risk')")
    threats_detected = cursor.fetchone()["cnt"]

    cursor.execute("SELECT COUNT(*) as cnt FROM analyses WHERE risk_level = 'Safe'")
    safe_emails = cursor.fetchone()["cnt"]

    cursor.execute("SELECT COUNT(*) as cnt FROM analyses WHERE risk_level IN ('Moderate', 'Suspicious')")
    suspicious_emails = cursor.fetchone()["cnt"]

    cursor.execute("SELECT AVG(risk_score) as avg_score FROM analyses")
    avg_score_res = cursor.fetchone()["avg_score"]
    avg_score = round(avg_score_res, 1) if avg_score_res is not None else 0.0

    # Risk level distribution
    cursor.execute("""
        SELECT risk_level, COUNT(*) as count
        FROM analyses
        GROUP BY risk_level
    """)
    distribution = {r["risk_level"]: r["count"] for r in cursor.fetchall()}

    # Top indicator categories
    cursor.execute("""
        SELECT category, COUNT(*) as count
        FROM threat_indicators
        GROUP BY category
        ORDER BY count DESC
        LIMIT 6
    """)
    top_categories = {r["category"]: r["count"] for r in cursor.fetchall()}

    # Recent 5 analyses
    cursor.execute("""
        SELECT id, created_at, sender, subject, risk_score, risk_level
        FROM analyses
        ORDER BY datetime(created_at) DESC
        LIMIT 5
    """)
    recent = [dict(r) for r in cursor.fetchall()]

    conn.close()
    return {
        "total_analyzed": total,
        "threats_detected": threats_detected,
        "safe_emails": safe_emails,
        "suspicious_emails": suspicious_emails,
        "average_risk_score": avg_score,
        "risk_distribution": distribution,
        "top_categories": top_categories,
        "recent_analyses": recent
    }

def delete_analysis(analysis_id: str) -> bool:
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM threat_indicators WHERE analysis_id = ?", (analysis_id,))
    cursor.execute("DELETE FROM analyses WHERE id = ?", (analysis_id,))
    conn.commit()
    deleted = cursor.rowcount > 0
    conn.close()
    return deleted

def get_setting(key: str, default: str = "") -> str:
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT value FROM settings WHERE key = ?", (key,))
    row = cursor.fetchone()
    conn.close()
    return row["value"] if row else default

def update_setting(key: str, value: str):
    conn = get_db_connection()
    cursor = conn.cursor()
    now = datetime.now(timezone.utc).isoformat()
    cursor.execute("""
        INSERT INTO settings (key, value, updated_at) VALUES (?, ?, ?)
        ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at
    """, (key, value, now))
    conn.commit()
    conn.close()

def get_all_settings() -> Dict[str, str]:
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT key, value FROM settings")
    settings = {r["key"]: r["value"] for r in cursor.fetchall()}
    conn.close()
    return settings
