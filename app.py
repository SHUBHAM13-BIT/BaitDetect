import os
import sys
from pathlib import Path
from flask import (
    Flask, render_template, request, redirect, url_for, flash,
    send_file, jsonify, abort
)
from werkzeug.utils import secure_filename

from config import Config
from database.database import (
    init_db, save_analysis, get_analysis_by_id, get_recent_analyses,
    get_dashboard_statistics, delete_analysis, get_all_settings, update_setting
)
from analyzer.pipeline import AnalysisPipeline
from reports.report_generator import ReportGenerator

# Initialize Flask application
app = Flask(__name__)
app.config.from_object(Config)

# Ensure database tables exist on startup
init_db()

def allowed_file(filename: str) -> bool:
    """Validate uploaded file extensions to prevent arbitrary file upload vulnerabilities."""
    ext = Path(filename).suffix.lower()
    return ext in Config.ALLOWED_EXTENSIONS

# ----------------- SECTION 1: OVERVIEW -----------------
@app.route("/")
def index():
    stats = get_dashboard_statistics()
    return render_template("index.html", stats=stats)

# ----------------- SECTION 2: EMAIL ANALYSIS -----------------
@app.route("/analyze", methods=["GET"])
def analyze_view():
    return render_template("analyze.html")

@app.route("/analyze/submit", methods=["POST"])
def submit_analysis():
    raw_content = request.form.get("raw_content", "").strip()
    uploaded_file = request.files.get("email_file")

    email_bytes = None

    # Handle file upload if provided
    if uploaded_file and uploaded_file.filename:
        filename = secure_filename(uploaded_file.filename)
        if not allowed_file(filename):
            flash("Invalid file format. Allowed file extensions: .eml, .txt, .msg, .header", "error")
            return redirect(url_for("analyze_view"))

        # Read file safely in memory
        try:
            email_bytes = uploaded_file.read()
        except Exception as e:
            flash(f"Failed to read uploaded file: {str(e)}", "error")
            return redirect(url_for("analyze_view"))
    elif raw_content:
        email_bytes = raw_content.encode("utf-8", errors="replace")

    if not email_bytes:
        flash("Empty email input. Please paste email headers/content or upload an email file.", "error")
        return redirect(url_for("analyze_view"))

    # Process through master analysis pipeline
    try:
        analysis_result = AnalysisPipeline.process_email(email_bytes)
        if not analysis_result.get("success"):
            flash(analysis_result.get("error", "Error analyzing email."), "error")
            return redirect(url_for("analyze_view"))

        # Generate audit PDF report
        try:
            pdf_path = ReportGenerator.generate_pdf(analysis_result)
            analysis_result["pdf_report_path"] = pdf_path
        except Exception as e:
            analysis_result["pdf_report_path"] = ""
            print(f"PDF generation warning: {str(e)}")

        # Save to SQLite Database
        save_analysis(analysis_result)

        flash(f"Analysis completed successfully. Risk Level: {analysis_result['risk_level']}", "success")
        return redirect(url_for("view_analysis", analysis_id=analysis_result["id"]))

    except Exception as e:
        flash(f"An unexpected error occurred during analysis: {str(e)}", "error")
        return redirect(url_for("analyze_view"))

# ----------------- VIEW SINGLE ANALYSIS -----------------
@app.route("/analysis/<analysis_id>")
def view_analysis(analysis_id: str):
    analysis_id = secure_filename(analysis_id)
    data = get_analysis_by_id(analysis_id)
    if not data:
        flash(f"Analysis record '{analysis_id}' not found.", "error")
        return redirect(url_for("index"))
    return render_template("analysis.html", analysis=data)

@app.route("/analysis/<analysis_id>/delete", methods=["POST"])
def delete_analysis_endpoint(analysis_id: str):
    analysis_id = secure_filename(analysis_id)
    data = get_analysis_by_id(analysis_id)
    if data and data.get("pdf_report_path"):
        try:
            pdf_p = Path(data["pdf_report_path"])
            if pdf_p.exists():
                pdf_p.unlink()
        except Exception:
            pass

    deleted = delete_analysis(analysis_id)
    if deleted:
        flash(f"Analysis {analysis_id} deleted successfully.", "success")
    else:
        flash("Failed to delete record.", "error")
    return redirect(url_for("history_view"))

# ----------------- SECTION 3: HEADER ANALYSIS -----------------
@app.route("/headers")
def header_analysis_view():
    recent = get_recent_analyses(limit=25)
    return render_template("section_headers.html", analyses=recent)

# ----------------- SECTION 4: URL INTELLIGENCE -----------------
@app.route("/urls")
def url_intelligence_view():
    recent = get_recent_analyses(limit=30)
    all_urls = []
    for r in recent:
        full_a = get_analysis_by_id(r["id"])
        if full_a and full_a.get("urls"):
            for u in full_a["urls"]:
                u_copy = dict(u)
                u_copy["analysis_id"] = r["id"]
                all_urls.append(u_copy)

    return render_template("section_urls.html", urls_list=all_urls, total_urls_count=len(all_urls))

# ----------------- SECTION 5: ATTACHMENT ANALYSIS -----------------
@app.route("/attachments")
def attachment_analysis_view():
    recent = get_recent_analyses(limit=30)
    all_attachments = []
    for r in recent:
        full_a = get_analysis_by_id(r["id"])
        if full_a and full_a.get("attachments"):
            for att in full_a["attachments"]:
                att_copy = dict(att)
                att_copy["analysis_id"] = r["id"]
                all_attachments.append(att_copy)

    return render_template("section_attachments.html", attachments_list=all_attachments, total_attachments_count=len(all_attachments))

# ----------------- SECTION 6: THREAT INDICATORS -----------------
@app.route("/indicators")
def threat_indicators_view():
    recent = get_recent_analyses(limit=25)
    all_indicators = []
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}

    for r in recent:
        full_a = get_analysis_by_id(r["id"])
        if full_a and full_a.get("indicators"):
            for ind in full_a["indicators"]:
                ind_copy = dict(ind)
                ind_copy["analysis_id"] = r["id"]
                all_indicators.append(ind_copy)
                sev = (ind.get("severity") or "low").lower()
                if sev in counts:
                    counts[sev] += 1

    return render_template("section_indicators.html", indicators=all_indicators, counts=counts)

# ----------------- SECTION 7: RISK ASSESSMENT -----------------
@app.route("/risk-assessment")
def risk_assessment_view():
    return render_template("section_risk.html")

# ----------------- SECTION 8: ANALYSIS HISTORY -----------------
@app.route("/history")
def history_view():
    records = get_recent_analyses(limit=100)
    return render_template("history.html", analyses=records)

@app.route("/history/export-csv")
def export_all_csv():
    records = get_recent_analyses(limit=500)
    csv_path = ReportGenerator.export_csv(records)
    return send_file(csv_path, mimetype="text/csv", as_attachment=True, download_name=Path(csv_path).name)

# ----------------- SECTION 9: REPORTS -----------------
@app.route("/reports")
def reports_view():
    records = get_recent_analyses(limit=50)
    return render_template("reports.html", analyses=records)

@app.route("/analysis/<analysis_id>/pdf")
def download_pdf(analysis_id: str):
    analysis_id = secure_filename(analysis_id)
    data = get_analysis_by_id(analysis_id)
    if not data:
        abort(404, description="Analysis not found")

    pdf_path = data.get("pdf_report_path")
    if not pdf_path or not Path(pdf_path).exists():
        # Re-generate PDF on demand
        pdf_path = ReportGenerator.generate_pdf(data)
        # update DB with regenerated path
        from database.database import get_db_connection
        conn = get_db_connection()
        conn.execute("UPDATE analyses SET pdf_report_path = ? WHERE id = ?", (pdf_path, analysis_id))
        conn.commit()
        conn.close()

    return send_file(pdf_path, as_attachment=True, download_name=f"Incident_Report_{analysis_id}.pdf")

@app.route("/analysis/<analysis_id>/json")
def export_json(analysis_id: str):
    analysis_id = secure_filename(analysis_id)
    data = get_analysis_by_id(analysis_id)
    if not data:
        abort(404, description="Analysis not found")

    return jsonify(data)

# ----------------- SECTION 10: SETTINGS -----------------
@app.route("/settings")
def settings_view():
    settings = get_all_settings()
    return render_template("settings.html", settings=settings)

@app.route("/settings/save", methods=["POST"])
def save_settings():
    vt_key = request.form.get("virustotal_api_key", "").strip()
    gsb_key = request.form.get("google_safe_browsing_api_key", "").strip()
    enable_dns = "true" if request.form.get("enable_live_dns") else "false"
    enable_intel = "true" if request.form.get("enable_threat_intel") else "false"
    strict_mode = "true" if request.form.get("strict_mode") else "false"

    update_setting("virustotal_api_key", vt_key)
    update_setting("google_safe_browsing_api_key", gsb_key)
    update_setting("enable_live_dns", enable_dns)
    update_setting("enable_threat_intel", enable_intel)
    update_setting("strict_mode", strict_mode)

    flash("Settings updated successfully.", "success")
    return redirect(url_for("settings_view"))

# ----------------- REST API -----------------
@app.route("/api/v1/analyze", methods=["POST"])
def api_analyze():
    raw_content = ""
    if request.is_json:
        raw_content = request.json.get("raw_content", "")
    elif "email_file" in request.files:
        f = request.files["email_file"]
        if f and f.filename and allowed_file(f.filename):
            raw_content = f.read().decode("utf-8", errors="replace")
    elif "raw_content" in request.form:
        raw_content = request.form.get("raw_content", "")

    if not raw_content:
        return jsonify({"success": False, "error": "Missing raw_content or email_file"}), 400

    try:
        result = AnalysisPipeline.process_email(raw_content)
        if not result.get("success"):
            return jsonify(result), 400

        pdf_path = ReportGenerator.generate_pdf(result)
        result["pdf_report_path"] = pdf_path
        save_analysis(result)
        return jsonify(result), 200
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

@app.route("/api/v1/health")
def api_health():
    return jsonify({
        "status": "operational",
        "service": "BaitDetect Phishing Detection Engine",
        "version": "2.6.0",
        "python": sys.version
    })

if __name__ == "__main__":
    app.run(host=Config.HOST, port=Config.PORT, debug=Config.DEBUG)
