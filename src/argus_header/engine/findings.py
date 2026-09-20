"""Shared helpers for constructing and normalizing findings."""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import asdict
from typing import Any

from argus_header.models.finding import Finding


def make_finding(
    id: str,
    category: str,
    severity: str,
    title: str,
    description: str = "",
    evidence: str = "",
    impact: str = "",
    recommendation: str = "",
    references: Iterable[str] = (),
    risk: str = "",
) -> Finding:
    """Convenience factory that keeps analyzer code concise.

    ``risk`` and ``impact`` are kept separate so consumers may display
    either a short labelled risk or a longer impact statement.
    """
    return Finding(
        id=id,
        category=category,
        severity=severity,
        title=title,
        description=description,
        evidence=evidence,
        impact=impact,
        recommendation=recommendation,
        references=list(references),
        risk=risk,
    )


def findings_to_dicts(findings: Iterable[Finding]) -> list[dict[str, Any]]:
    """Serialize a collection of findings to report dictionaries."""
    return [f.to_dict() for f in findings]


def dicts_to_findings(data: Iterable[dict[str, Any]]) -> list[Finding]:
    """Convert report dictionaries back into Finding objects."""
    return [Finding.from_dict(d) for d in data]


def as_dicts(findings: Iterable[Any]) -> list[dict[str, Any]]:
    """Normalize a mixed iterable of Finding objects or dicts to dicts."""
    result: list[dict[str, Any]] = []
    for f in findings:
        if isinstance(f, Finding):
            result.append(f.to_dict())
        elif isinstance(f, Mapping):
            result.append(dict(f))
        elif f is None:
            continue
        else:
            result.append(asdict(f))
    return result
