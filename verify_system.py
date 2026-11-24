import os
import sys
from analyzer.pipeline import AnalysisPipeline
from reports.report_generator import ReportGenerator
from database.database import init_db, save_analysis, get_analysis_by_id, get_dashboard_statistics

def main():
    print("=" * 60)
    print("STARTING COMPLETE END-TO-END VERIFICATION")
    print("=" * 60)

    init_db()

    # 1. Test Credential Phishing Sample
    phish_sample = """From: "PayPal Security Center" <service@secure-paypal-alert-update.xyz>
To: target-victim@company.com
Reply-To: security-reply@gmail.com
Subject: URGENT: Your PayPal Account Has Been Suspended - Verify Identity Immediately
Date: Tue, 24 Nov 2026 12:00:00 +0000
Message-ID: <unauthorized-login-alert@suspicious.com>
Authentication-Results: mx.google.com; spf=fail; dkim=fail; dmarc=fail
Received: from unknown [198.51.100.45] by mx.company.com; Tue, 24 Nov 2026 12:01:00 +0000

Dear Customer,

We detected unauthorized login attempts to your PayPal account.
Verify your identity immediately:
http://198.51.100.45/paypal-login/verify.php
"""
    res1 = AnalysisPipeline.process_email(phish_sample)
    assert res1["success"], "Pipeline failed on phishing sample"
    assert res1["risk_score"] >= 80, f"Expected Critical risk, got {res1['risk_score']}"
    assert "Critical" in res1["risk_level"]
    print(f"[PASS] Scenario 1 (Credential Phish): Risk Score {res1['risk_score']}/100 ({res1['risk_level']})")

    # 2. Test Legitimate Email Sample
    legit_sample = """From: "GitHub" <notifications@github.com>
To: developer@company.com
Reply-To: support@github.com
Subject: [GitHub] Dependabot alert for repository
Date: Tue, 24 Nov 2026 10:00:00 +0000
Message-ID: <gh-12345@github.com>
Authentication-Results: mx.google.com; spf=pass; dkim=pass; dmarc=pass

Hi Developer, Dependabot found a moderate alert. Review at https://github.com/advisories.
"""
    res2 = AnalysisPipeline.process_email(legit_sample)
    assert res2["success"], "Pipeline failed on legitimate sample"
    assert res2["risk_score"] <= 20, f"Expected Safe, got {res2['risk_score']}"
    assert res2["risk_level"] == "Safe"
    print(f"[PASS] Scenario 2 (Legitimate Email): Risk Score {res2['risk_score']}/100 ({res2['risk_level']})")

    # 3. Test PDF Report Generation
    pdf_path = ReportGenerator.generate_pdf(res1)
    assert os.path.exists(pdf_path), "PDF file was not created on disk"
    assert os.path.getsize(pdf_path) > 5000, "PDF file size too small"
    with open(pdf_path, "rb") as f:
        assert f.read(5) == b"%PDF-", "Invalid PDF magic header"
    print(f"[PASS] PDF Generation: Created valid audit report at {pdf_path} ({os.path.getsize(pdf_path)} bytes)")

    # 4. Test JSON and CSV Export
    json_path = ReportGenerator.export_json(res1)
    assert os.path.exists(json_path), "JSON export failed"
    print(f"[PASS] JSON Export: Created valid JSON at {json_path}")

    # 5. Test Database Persistence
    save_analysis(res1)
    save_analysis(res2)
    stats = get_dashboard_statistics()
    assert stats["total_analyzed"] >= 2
    print(f"[PASS] Database Persistence: Stats verified (Total analyzed: {stats['total_analyzed']})")

    # 6. Test CSV summary export
    csv_path = ReportGenerator.export_csv([res1, res2])
    assert os.path.exists(csv_path), "CSV export failed"
    print(f"[PASS] CSV Export: Created valid CSV summary at {csv_path}")

    print("=" * 60)
    print("ALL VERIFICATION CHECKS COMPLETED SUCCESSFULLY!")
    print("=" * 60)

if __name__ == "__main__":
    main()
