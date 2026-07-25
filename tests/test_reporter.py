import os
import json
from src.argus.reporter import print_report
from src.argus.reporter import save_json as reporter_save_json

def test_reporter_saves_json(tmp_path):
    response_data = {
        "success": True,
        "url": "https://example.com",
        "status_code": 200,
        "headers": {"Server": "nginx"},
    }

    findings = [
        {
            "category": "Security",
            "issue": "Missing CSP",
            "severity": "HIGH",
            "risk": "XSS risk",
            "fix": "Add CSP header"
        }
    ]

    file_path = tmp_path / "example.json"

    # Save JSON report
    reporter_save_json(response_data, findings, file_path)

    assert os.path.exists(file_path)

    with open(file_path, "r") as f:
        data = json.load(f)

    assert data["target"] == "https://example.com"
    assert data["status"] == 200
    assert isinstance(data["findings"], list)
