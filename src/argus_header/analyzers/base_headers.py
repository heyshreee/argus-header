"""Base security header and information-leakage analysis.

Covers headers that do not belong to a single deep family: X-Frame-Options,
X-Content-Type-Options, and server/framework information leakage. These are
present in the v0.8 engine for parity with the v0.7 default rules while using
the structured v0.8 finding format.
"""

from __future__ import annotations

from collections.abc import Mapping

from argus_header.engine.findings import make_finding
from argus_header.engine.references import references_for


def analyze_base_headers(headers: Mapping[str, str]) -> list[dict]:
    """Analyze XFO, XCTO and infoleak headers."""
    findings: list[dict] = []

    # X-Frame-Options (SUPERSEDED by CSP frame-ancestors when present).
    has_csp = headers.get("content-security-policy")
    xfo = headers.get("x-frame-options")
    if xfo is None and not has_csp:
        findings.append(
            base_finding(
                "ARGUS-XFO-001",
                "Missing X-Frame-Options",
                "MEDIUM",
                "x-frame-options header absent",
                "The page may be embeddable in third-party frames, enabling "
                "clickjacking.",
                "Set X-Frame-Options: DENY/SAMEORIGIN or frame-ancestors in CSP.",
                "xfo",
            )
        )

    # X-Content-Type-Options
    xcto = headers.get("x-content-type-options")
    if xcto is None:
        findings.append(
            base_finding(
                "ARGUS-XCTO-001",
                "Missing X-Content-Type-Options",
                "MEDIUM",
                "x-content-type-options header absent",
                "Browsers may MIME-sniff the response body, enabling content "
                "type confusion and XSS.",
                "Set X-Content-Type-Options: nosniff.",
                "xcto",
            )
        )
    elif xcto.strip().lower() != "nosniff":
        findings.append(
            base_finding(
                "ARGUS-XCTO-002",
                "Invalid X-Content-Type-Options value",
                "MEDIUM",
                f"X-Content-Type-Options: {xcto}",
                "Only 'nosniff' is a recognized value; other values are ignored.",
                "Use X-Content-Type-Options: nosniff.",
                "xcto",
            )
        )

    # Server header leak
    server = headers.get("server")
    if server:
        findings.append(
            base_finding(
                "ARGUS-SERVER-001",
                "Server header exposes technology",
                "LOW",
                f"Server: {server}",
                (
                    "The Server header reveals the server/version, which helps "
                    "attackers verify exposed vulnerabilities."
                ),
                "Suppress or obfuscate the Server header.",
                "server_leak",
            )
        )

    # X-Powered-By leak
    xpb = headers.get("x-powered-by")
    if xpb:
        findings.append(
            base_finding(
                "ARGUS-SERVER-002",
                "X-Powered-By exposes framework",
                "MEDIUM",
                f"X-Powered-By: {xpb}",
                (
                    "The X-Powered-By header reveals the framework and version, "
                    "aiding targeted exploitation."
                ),
                "Remove the X-Powered-By header in the framework configuration.",
                "x_powered_by",
            )
        )

    return findings


def base_finding(
    rule_id: str,
    title: str,
    severity: str,
    evidence: str,
    impact: str,
    recommendation: str,
    ref_key: str,
) -> dict:
    return make_finding(
        id=rule_id,
        category=(
            "Browser"
            if rule_id.startswith(("ARGUS-XFO", "ARGUS-XCTO"))
            else "Isolation"
        ),
        severity=severity,
        title=title,
        description=impact,
        evidence=evidence,
        impact=impact,
        recommendation=recommendation,
        risk=impact,
        references=references_for(ref_key),
    ).to_dict()
