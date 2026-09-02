"""Tests for SARIF 2.1.0 output."""

import json

from argus_header.engine.scoring import calculate_score_2
from argus_header.output.json_report import build_report
from argus_header.output.sarif import (
    SARIF_VERSION,
    build_sarif,
    render_sarif,
    save_sarif,
)


def sample_findings():
    return [
        {
            "id": "ARGUS-CSP-003",
            "severity": "HIGH",
            "title": "Weak Content Security Policy",
            "impnact": "",
        }
    ]


def test_sarif_version():
    assert SARIF_VERSION == "2.1.0"


def test_sarif_document_structure():
    findings = [
        {
            "id": "ARGUS-CSP-003",
            "severity": "HIGH",
            "title": "Weak CSP",
            "impact": "XSS",
        },
        {
            "id": "ARGUS-CORS-001",
            "severity": "MEDIUM",
            "title": "Wildcard CORS",
            "impact": "Abuse",
        },
    ]

    sarif = build_sarif(findings, "https://example.com")

    assert sarif["version"] == "2.1.0"
    run = sarif["runs"][0]
    assert run["tool"]["driver"]["name"] == "Argus Header"
    assert len(run["results"]) == 2
    assert len(run["tool"]["driver"]["rules"]) == 2


def test_sarif_level_mapping():
    sarif = build_sarif(
        [
            {"id": "a", "severity": "CRITICAL", "title": "c"},
            {"id": "b", "severity": "HIGH", "title": "h"},
            {"id": "c", "severity": "MEDIUM", "title": "m"},
            {"id": "d", "severity": "LOW", "title": "l"},
        ],
        "https://example.com",
    )

    levels = [r["level"] for r in sarif["runs"][0]["results"]]

    assert levels == ["error", "error", "warning", "note"]


def test_sarif_serializable():
    sarif = build_sarif(sample_findings(), "https://example.com")
    assert json.loads(render_sarif(sarif))["version"] == SARIF_VERSION


def test_sarif_integration_with_report(tmp_path):
    findings = [
        {"id": "ARGUS-CSP-001", "severity": "HIGH", "title": "Missing CSP"},
    ]
    score = calculate_score_2(findings)
    report = build_report("https://example.com", {}, findings, score, "id1", status=200)

    sarif = build_sarif(report["findings"], report["scan"]["target"])
    path = tmp_path / "scan.sarif"
    save_sarif(sarif, str(path))

    loaded = json.loads(path.read_text(encoding="utf-8"))
    assert loaded["runs"][0]["results"][0]["ruleId"] == "ARGUS-CSP-001"
