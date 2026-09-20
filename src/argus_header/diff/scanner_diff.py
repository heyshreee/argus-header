"""Comparison mode: diff two scan reports.

Loads two prior JSON reports (before/after) and summarises the change in
security posture: score delta, findings that were fixed (present in the
before report but not the after) and findings that are new.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any


def _findings_of(report: Mapping[str, Any]) -> list[dict]:
    return list(report.get("findings", []) or [])


def _score_of(report: Mapping[str, Any]) -> int:
    return int(report.get("score", {}).get("value", 0))


def _finding_key(f: Mapping[str, Any]) -> str:
    # Two findings are considered the same rule instance when they share
    # a rule id and the same substantive evidence.
    rule_id = str(f.get("id", ""))
    evidence = str(f.get("evidence", "") or f.get("issue", "") or f.get("title", ""))
    return f"{rule_id}::{evidence}"


def scan_diff(before: Mapping[str, Any], after: Mapping[str, Any]) -> dict[str, Any]:
    """Compare a before/after report pair and return a diff summary."""
    before_findings = _findings_of(before)
    after_findings = _findings_of(after)

    before_keys = {_finding_key(f) for f in before_findings}
    after_keys = {_finding_key(f) for f in after_findings}

    fixed_keys = before_keys - after_keys
    new_keys = after_keys - before_keys

    fixed = [
        {"id": f.get("id"), "title": f.get("title") or f.get("issue")}
        for f in before_findings
        if _finding_key(f) in fixed_keys
    ]
    new = [
        {"id": f.get("id"), "title": f.get("title") or f.get("issue")}
        for f in after_findings
        if _finding_key(f) in new_keys
    ]

    score_before = _score_of(before)
    score_after = _score_of(after)
    delta = score_after - score_before

    if delta > 0:
        posture = "IMPROVED"
    elif delta < 0:
        posture = "DEGRADED"
    else:
        posture = "UNCHANGED"

    return {
        "score_before": score_before,
        "score_after": score_after,
        "score_delta": delta,
        "fixed": fixed,
        "new": new,
        "posture": posture,
    }
