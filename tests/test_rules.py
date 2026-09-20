"""Tests for the rules engine and rule library."""

from argus_header.engine.rules import RULES, normalize_headers, run_rule, run_rules
from argus_header.models.configuration import Configuration


def test_rules_are_registered():
    keys = {r.key for r in RULES}

    assert {
        "csp",
        "cors",
        "cookies",
        "hsts",
        "cache",
        "cross_origin",
        "referrer",
        "permissions",
        "base_headers",
    } <= keys


def test_normalize_headers_lowercases():
    normalized = normalize_headers({"Content-Security-Policy": "default-src 'self'"})

    assert "content-security-policy" in normalized


def test_run_rules_detects_weak_csp():
    findings = run_rules({"Content-Security-Policy": "default-src *"})

    assert any(f["id"] == "ARGUS-CSP-102" for f in findings)


def test_run_rule_single_family():
    findings = run_rule("hsts", {"strict-transport-security": "max-age=30"})

    assert all(f["id"].startswith("ARGUS-HSTS") for f in findings)


def test_run_rules_with_csp_disabled():
    config = Configuration.loads("rules:\n  csp: false")

    findings = run_rules({"content-security-policy": "default-src *"}, config=config)

    assert not any(f["id"].startswith("ARGUS-CSP") for f in findings)


def test_run_rules_case_insensitive_headers():
    findings = run_rules({"SET-COOKIE": "session=abc"})

    assert any(f["id"].startswith("ARGUS-COOKIE") for f in findings)


def test_findings_have_structured_fields():
    findings = run_rules({"Server": "nginx/1.18"})

    for f in findings:
        assert "id" in f
        assert "severity" in f
        assert "title" in f
        assert "evidence" in f
        assert "references" in f
