"""Referrer-Policy analysis."""

from __future__ import annotations

from collections.abc import Mapping

from argus_header.engine.findings import make_finding
from argus_header.engine.references import references_for

# Values the browser supports, from most to least privacy preserving.
SUPPORTED = {
    "no-referrer",
    "no-referrer-when-downgrade",
    "same-origin",
    "origin",
    "strict-origin",
    "origin-when-cross-origin",
    "strict-origin-when-cross-origin",
    "unsafe-url",
}

# Values that leak the full URL across origins.
LEAKY = {"unsafe-url", "no-referrer-when-downgrade"}


def analyze_referrer(headers: Mapping[str, str]) -> list[dict]:
    """Analyze the Referrer-Policy header."""
    findings: list[dict] = []

    value = headers.get("referrer-policy")
    if value is None:
        findings.append(
            referrer_finding(
                "ARGUS-REFERRER-001",
                "Missing Referrer-Policy",
                "LOW",
                "referrer-policy header absent",
                (
                    "Browsers apply a restrictive default, but an explicit "
                    "policy is recommended to prevent leakage of the full URL."
                ),
                "Set Referrer-Policy (e.g. strict-origin-when-cross-origin).",
            )
        )
        return findings

    # A comma-separated list (fallback chain) may be present.
    normalized_value = value.strip().lower()
    if normalized_value not in SUPPORTED and not any(
        v in normalized_value for v in SUPPORTED
    ):
        findings.append(
            referrer_finding(
                "ARGUS-REFERRER-002",
                "Invalid Referrer-Policy value",
                "LOW",
                value,
                "An invalid value is ignored by the browser.",
                "Use one of the standard Referrer-Policy values.",
            )
        )

    if any(leaky in normalized_value for leaky in LEAKY):
        findings.append(
            referrer_finding(
                "ARGUS-REFERRER-003",
                "Referrer-Policy leaks full URL",
                "MEDIUM",
                value,
                (
                    "The configured policy can send the full URL (including "
                    "query strings) to external origins."
                ),
                "Prefer strict-origin-when-cross-origin or same-origin.",
            )
        )

    return findings


def referrer_finding(
    rule_id: str,
    title: str,
    severity: str,
    evidence: str,
    impact: str,
    recommendation: str,
) -> dict:
    return make_finding(
        id=rule_id,
        category="Referrer",
        severity=severity,
        title=title,
        description=impact,
        evidence=evidence,
        impact=impact,
        recommendation=recommendation,
        risk=impact,
        references=references_for("referrer"),
    ).to_dict()
