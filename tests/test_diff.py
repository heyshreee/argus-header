"""Tests for comparison/diff mode."""

from argus_header.diff.scanner_diff import _finding_key, scan_diff


def _finding(rule_id, evidence=""):
    return {"id": rule_id, "evidence": evidence, "title": rule_id}


def _report(findings, score):
    return {"findings": findings, "score": {"value": score}}


def test_identical_reports_no_change():
    findings = [_finding("ARGUS-CSP-001", "absent")]
    before = _report(findings, 55)
    after = _report([_finding("ARGUS-CSP-001", "absent")], 55)

    result = scan_diff(before, after)

    assert result["fixed"] == []
    assert result["new"] == []
    assert result["posture"] == "UNCHANGED"
    assert result["score_delta"] == 0


def test_fixed_findings_detected():
    before = _report([_finding("ARGUS-CSP-001", "absent")], 55)
    after = _report([], 95)

    result = scan_diff(before, after)

    assert any(f["id"] == "ARGUS-CSP-001" for f in result["fixed"])
    assert result["new"] == []
    assert result["posture"] == "IMPROVED"
    assert result["score_delta"] == 40


def test_new_findings_detected():
    before = _report([], 95)
    after = _report([_finding("ARGUS-CORS-001", "Access-Control-Allow-Origin: *")], 55)

    result = scan_diff(before, after)

    assert any(f["id"] == "ARGUS-CORS-001" for f in result["new"])
    assert result["fixed"] == []
    assert result["posture"] == "DEGRADED"


def test_finding_key_uses_rule_id_and_evidence():
    a = {"id": "ARGUS-X-001", "evidence": "evidence-a"}
    b = {"id": "ARGUS-X-001", "evidence": "evidence-b"}
    assert _finding_key(a) != _finding_key(b)
