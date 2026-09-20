"""Permissions-Policy analysis."""

from __future__ import annotations

from collections.abc import Mapping

from argus_header.engine.findings import make_finding
from argus_header.engine.references import references_for


def analyze_permissions(headers: Mapping[str, str]) -> list[dict]:
    """Analyze the Permissions-Policy (Feature-Policy) header."""
    findings: list[dict] = []

    value = headers.get("permissions-policy")
    if value is None:
        findings.append(
            perm_finding(
                "ARGUS-PERMISSIONS-001",
                "Missing Permissions-Policy",
                "LOW",
                "permissions-policy header absent",
                (
                    "Powerful browser features (camera, geolocation, etc.) may "
                    "be available to embedded content by default."
                ),
                "Define a Permissions-Policy to restrict sensitive features.",
            )
        )
        return findings

    if not value.strip():
        findings.append(
            perm_finding(
                "ARGUS-PERMISSIONS-002",
                "Empty Permissions-Policy",
                "LOW",
                value,
                "An empty policy has no effect.",
                "Provide feature allowlists in the policy.",
            )
        )

    # A useful heuristic: if the policy uses '*' broadly it is permissive.
    broad_allow = [d for d in value.split(",") if "*" in d]
    if len(broad_allow) >= 3:
        findings.append(
            perm_finding(
                "ARGUS-PERMISSIONS-003",
                "Permissions-Policy broadly permissive",
                "MEDIUM",
                value,
                (
                    "Several features allow all origins, reducing the policy's "
                    "ability to restrict sensitive capabilities."
                ),
                "Restrict feature allowlists to same-origin only.",
            )
        )

    return findings


def perm_finding(
    rule_id: str,
    title: str,
    severity: str,
    evidence: str,
    impact: str,
    recommendation: str,
) -> dict:
    return make_finding(
        id=rule_id,
        category="Permissions",
        severity=severity,
        title=title,
        description=impact,
        evidence=evidence,
        impact=impact,
        recommendation=recommendation,
        risk=impact,
        references=references_for("permissions"),
    ).to_dict()
