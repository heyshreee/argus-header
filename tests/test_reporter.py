import json
import os

from argus_header.reporter import build_json_report
from argus_header.reporter import save_json as reporter_save_json


def make_canonical_report():
    response_data = {
        "success": True,
        "url": "https://example.com",
        "status_code": 200,
        "headers": {"Server": "nginx"},
    }

    findings = [
        {
            "id": "SEC-001",
            "category": "Security",
            "issue": "Missing CSP",
            "severity": "HIGH",
            "risk": "XSS risk",
            "fix": "Add CSP header"
        }
    ]

    score = {
        "score": 80,
        "grade": "B",
        "risk_level": "HIGH",
        "penalty": 20,
    }

    return build_json_report(
        response_data,
        findings,
        score,
        "test1234",
        "https://example.com",
    )


def test_reporter_saves_json(tmp_path):
    file_path = tmp_path / "example.json"

    # Save JSON report from the canonical report object
    reporter_save_json(make_canonical_report(), str(file_path))

    assert os.path.exists(file_path)

    with open(file_path, "r") as f:
        data = json.load(f)

    assert data["scan"]["target"] == "https://example.com"
    assert data["scan"]["status"] == 200
    assert isinstance(data["findings"], list)
    assert data["schema_version"] == "0.7"
    assert data["score"]["value"] == 80
    assert "timestamp" in data["scan"]
