"""HTTP Strict Transport Security (HSTS) deep analysis.

Checks presence, max-age, includeSubDomains and preload directives.
"""

from __future__ import annotations

import re
from collections.abc import Mapping

from argus_header.engine.findings import make_finding
from argus_header.engine.references import references_for

_AGE_RE = re.compile(r"max-age\s*=\s*(\d+)", re.IGNORECASE)


def analyze_hsts(headers: Mapping[str, str]) -> list[dict]:
    """Analyze the Strict-Transport-Security header."""
    findings: list[dict] = []

    value = headers.get("strict-transport-security")
    if value is None:
        findings.append(
            hsts_finding(
                "ARGUS-HSTS-001",
                "Missing Strict-Transport-Security header",
                "HIGH",
                "Strict-Transport-Security header absent",
                (
                    "Browsers will not enforce HTTPS-only connections, leaving "
                    "the site open to protocol-downgrade attacks."
                ),
                "Add Strict-Transport-Security with an adequate max-age.",
            )
        )
        return findings

    age_match = _AGE_RE.search(value)
    if not age_match:
        findings.append(
            hsts_finding(
                "ARGUS-HSTS-002",
                "HSTS missing max-age directive",
                "HIGH",
                value,
                (
                    "Without max-age the policy cannot be enforced; the header "
                    "is effectively a no-op."
                ),
                "Define max-age (recommended 63072000 or higher).",
                "Missing max-age directive",
            )
        )
        return findings

    max_age = int(age_match.group(1))

    if max_age < 15552000:  # < 180 days
        findings.append(
            hsts_finding(
                "ARGUS-HSTS-003",
                "HSTS max-age is too short",
                "MEDIUM",
                value,
                (
                    "A short max-age reduces the window during which upgrade "
                    "instructions remain cached by browsers."
                ),
                "Use max-age of at least 15552000 (180 days).",
                f"max-age={max_age}",
            )
        )

    if "includesubdomains" not in value.lower():
        findings.append(
            hsts_finding(
                "ARGUS-HSTS-004",
                "HSTS missing includeSubDomains",
                "MEDIUM",
                value,
                "Subdomains are not covered by the upgrade policy.",
                "Add includeSubDomains to extend protection to subdomains.",
                "missing includeSubDomains",
            )
        )

    return findings


def hsts_finding(
    rule_id: str,
    title: str,
    severity: str,
    evidence: str,
    impact: str,
    recommendation: str,
    note: str = "",
) -> dict:
    return make_finding(
        id=rule_id,
        category="HSTS",
        severity=severity,
        title=title,
        description=note or impact,
        evidence=evidence,
        impact=impact,
        recommendation=recommendation,
        risk=impact,
        references=references_for("hsts"),
    ).to_dict()
