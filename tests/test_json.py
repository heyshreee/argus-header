"""Tests for the v0.8 JSON report builder."""

import json

from argus_header.engine.scoring import calculate_score_2
from argus_header.output.json_report import (
    SCHEMA_VERSION,
    build_report,
    load_report,
    render_json,
    save_report,
)


def _report():
    findings = [
        {
            "id": "ARGUS-CSP-003",
            "severity": "HIGH",
            "title": "Weak Content Security Policy",
            "evidence": "script-src 'unsafe-inline'",
        }
    ]
    score = calculate_score_2(findings)
    return build_report(
        target="https://example.com",
        headers={"Server": "nginx"},
        findings=findings,
        score=score,
        scan_id="abc12345",
        method="GET",
        duration=1.23,
        status=200,
        final_url="https://example.com/",
    )


def test_schema_version_is_0_8():
    assert SCHEMA_VERSION == "0.8"


def test_report_has_expected_structure():
    report = _report()

    assert report["schema_version"] == "0.8"
    assert report["score"]["value"] > 0
    assert report["score"]["categories"]
    assert report["score"]["breakdown"]["HIGH"] == 1
    assert report["summary"]["total_findings"] == 1
    assert report["findings"][0]["id"] == "ARGUS-CSP-003"


def test_report_serializes_to_json():
    serialized = render_json(_report())
    assert json.loads(serialized)["schema_version"] == "0.8"


def test_save_and_load_roundtrip(tmp_path):
    path = tmp_path / "report.json"
    save_report(_report(), str(path))

    loaded = load_report(str(path))

    assert loaded["scan"]["target"] == "https://example.com"
    assert loaded["findings"][0]["id"] == "ARGUS-CSP-003"


def test_score_data_repr_in_build_report():
    report = _report()
    assert isinstance(report["score"], dict)


def test_machine_readable_example_match():
    """The documented --json example shape must hold."""
    report = _report()

    assert report["scan"]["target"] == "https://example.com"
    assert isinstance(report["score"]["value"], int)
    assert "grade" in report["score"]
    assert report["findings"][0]["severity"] == "HIGH"
