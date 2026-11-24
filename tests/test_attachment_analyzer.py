import pytest
from analyzer.attachment_analyzer import AttachmentAnalyzer

def test_attachment_double_extension():
    attachments = [{
        "filename": "invoice_october.pdf.exe",
        "content_type": "application/octet-stream",
        "size_bytes": 10240,
        "sha256": "abcdef123456",
        "is_inline": False
    }]
    res = AttachmentAnalyzer.analyze(attachments)
    assert res["suspicious_attachments_count"] == 1
    ind_names = [i["name"] for i in res["indicators"]]
    assert any("Deceptive Double Extension" in name for name in ind_names)

def test_attachment_direct_executable():
    attachments = [{
        "filename": "payroll_update.vbs",
        "content_type": "text/plain",
        "size_bytes": 2048,
        "sha256": "123456abcdef",
        "is_inline": False
    }]
    res = AttachmentAnalyzer.analyze(attachments)
    assert res["suspicious_attachments_count"] == 1
    ind_names = [i["name"] for i in res["indicators"]]
    assert any("High-Risk Executable" in name for name in ind_names)

def test_attachment_safe_pdf():
    attachments = [{
        "filename": "meeting_agenda.pdf",
        "content_type": "application/pdf",
        "size_bytes": 54000,
        "sha256": "fedcba987654",
        "is_inline": False
    }]
    res = AttachmentAnalyzer.analyze(attachments)
    assert res["suspicious_attachments_count"] == 0
