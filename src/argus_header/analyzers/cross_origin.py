"""Cross-Origin isolation policy analysis (COOP, COEP, CORP)."""

from __future__ import annotations

from collections.abc import Mapping

from argus_header.engine.findings import make_finding
from argus_header.engine.references import references_for


def analyze_cross_origin(headers: Mapping[str, str]) -> list[dict]:
    """Analyze Cross-Origin-Opener/Embedder/Resource policies."""
    findings: list[dict] = []

    coop = headers.get("cross-origin-opener-policy")
    coep = headers.get("cross-origin-embedder-policy")
    corp = headers.get("cross-origin-resource-policy")

    if coop is None:
        findings.append(
            xo_finding(
                "ARGUS-COOP-001",
                "Missing Cross-Origin-Opener-Policy",
                "cross-origin-opener-policy header absent",
                "LOW",
                "Without a policy, pages may be opened in the same browsing "
                "context group as cross-origin documents.",
                "Set Cross-Origin-Opener-Policy: same-origin.",
            )
        )
    elif (
        "same-origin" not in coop.lower()
        and "same-origin-allow-popups" not in coop.lower()
    ):
        findings.append(
            xo_finding(
                "ARGUS-COOP-002",
                "Cross-Origin-Opener-Policy is weak",
                coop,
                "LOW",
                "An unsafe value fails to isolate the browsing context group.",
                "Use same-origin or same-origin-allow-popups.",
            )
        )

    if coep is None:
        findings.append(
            xo_finding(
                "ARGUS-COEP-001",
                "Missing Cross-Origin-Embedder-Policy",
                "cross-origin-embedder-policy header absent",
                "LOW",
                "Without a policy, cross-origin subresources (incl. certain "
                "features such as SharedArrayBuffer) are not gated.",
                "Set Cross-Origin-Embedder-Policy: require-corp when needed.",
            )
        )

    if corp is None:
        findings.append(
            xo_finding(
                "ARGUS-CORP-001",
                "Missing Cross-Origin-Resource-Policy",
                "cross-origin-resource-policy header absent",
                "LOW",
                "Resources may be loadable by cross-origin sites.",
                "Set a Cross-Origin-Resource-Policy (same-origin/same-site/cross-origin).",
            )
        )

    # COEP: require-corp without CORP can break resource loading; flag the
    # absence of CORP when COEP requires it.
    if coep and "require-corp" in coep.lower() and corp is None:
        findings.append(
            xo_finding(
                "ARGUS-COEP-002",
                "COEP require-corp without CORP resources",
                coep,
                "MEDIUM",
                "require-corp embeds must provide CORP/CORS headers; missing "
                "CORP may cause subresources to be blocked.",
                "Ensure embedded resources send an appropriate CORP header.",
            )
        )

    return findings


def xo_finding(
    rule_id: str,
    title: str,
    evidence: str,
    severity: str,
    impact: str,
    recommendation: str,
) -> dict:
    return make_finding(
        id=rule_id,
        category="Cross-Origin",
        severity=severity,
        title=title,
        description=impact,
        evidence=evidence,
        impact=impact,
        recommendation=recommendation,
        risk=impact,
        references=references_for("cross_origin"),
    ).to_dict()
