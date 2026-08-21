from argus_header.html_report import render_html, save_html


def sample_report():
    return {
        "tool": {
            "name": "Argus Header",
            "version": "0.7.0",
        },
        "scan": {
            "target": "https://example.com",
            "final_url": "https://example.com/",
            "status": 200,
            "method": "GET",
            "timestamp": "2026-08-22T00:00:00+00:00",
            "duration_seconds": 0.42,
        },
        "score": {
            "value": 80,
            "grade": "B",
            "risk_level": "HIGH",
            "penalty": 20,
        },
        "summary": {
            "total_findings": 1,
            "high": 1,
            "medium": 0,
            "low": 0,
        },
        "findings": [
            {
                "id": "SEC-001",
                "category": "Security",
                "issue": "Missing Content-Security-Policy",
                "severity": "HIGH",
                "risk": "XSS risk.",
                "fix": "Add CSP.",
            }
        ],
        "headers": {
            "Content-Type": "text/html",
        },
    }


def test_html_report_contains_score_and_findings():
    html = render_html(sample_report())

    assert "<!DOCTYPE html>" in html
    assert "Argus Header Security Report" in html
    assert "80/100" in html
    assert "Grade B" in html
    assert "SEC-001" in html
    assert "Missing Content-Security-Policy" in html
    assert "Content-Type" in html


def test_html_escapes_untrusted_content():
    report = sample_report()
    report["scan"]["target"] = "https://example.com/?x=<script>alert(1)</script>"
    report["findings"] = []
    report["summary"] = {"total_findings": 0, "high": 0, "medium": 0, "low": 0}
    report["headers"] = {}

    html = render_html(report)

    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;" in html


def test_html_escapes_malicious_header_values():
    report = sample_report()
    report["headers"] = {"Server": "<script>evil</script>"}

    html = render_html(report)

    assert "<script>evil</script>" not in html


def test_save_html_writes_file(tmp_path):
    file_path = tmp_path / "report.html"

    save_html(sample_report(), str(file_path))

    content = file_path.read_text(encoding="utf-8")

    assert content.startswith("<!DOCTYPE html>")
