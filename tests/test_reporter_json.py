import json

from argus_header.reporter import build_json_report


def test_json_report_structure():
    response = {
        "success": True,
        "url": "https://example.com/",
        "status_code": 200,
        "headers": {
            "Content-Type": "text/html",
        },
    }

    findings = [
        {
            "id": "SEC-001",
            "category": "Security",
            "issue": "Missing Content-Security-Policy",
            "severity": "HIGH",
            "risk": "XSS risk.",
            "fix": "Add CSP.",
        }
    ]

    score = {
        "score": 80,
        "grade": "B",
        "risk_level": "HIGH",
        "penalty": 20,
        "total_findings": 1,
    }

    report = build_json_report(
        response,
        findings,
        score,
        "abc12345",
        "https://example.com",
    )

    assert report["schema_version"] == "0.7"
    assert report["tool"]["name"] == "Argus Header"

    assert report["scan"]["target"] == "https://example.com"
    assert report["scan"]["status"] == 200

    assert report["score"]["value"] == 80
    assert report["score"]["grade"] == "B"

    assert report["summary"]["total_findings"] == 1
    assert report["summary"]["high"] == 1

    assert report["findings"][0]["id"] == "SEC-001"


def test_json_is_serializable():
    response = {
        "success": True,
        "url": "https://example.com/",
        "status_code": 200,
        "headers": {},
    }

    report = build_json_report(
        response,
        [],
        {
            "score": 100,
            "grade": "A",
            "risk_level": "LOW",
            "penalty": 0,
            "total_findings": 0,
        },
        "abc12345",
        "https://example.com",
    )

    encoded = json.dumps(report)

    assert encoded


def test_timestamp_is_iso8601_utc():
    response = {"success": True, "url": "u", "status_code": 200, "headers": {}}

    report = build_json_report(
        response, [], {"score": 100, "grade": "A", "risk_level": "LOW", "penalty": 0},
        "id1", "t",
    )

    stamp = report["scan"]["timestamp"]

    assert "T" in stamp
    assert stamp.endswith("+00:00")
