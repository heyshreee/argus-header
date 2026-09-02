"""Cross-Origin Resource Sharing (CORS) deep analysis.

Identifies dangerous configurations such as wildcard origins combined
with credentials, and inspects methods, headers, exposed headers and
max-age.
"""

from __future__ import annotations

from collections.abc import Mapping

from argus_header.engine.findings import make_finding
from argus_header.engine.references import references_for


def analyze_cors(headers: Mapping[str, str]) -> list[dict]:
    """Analyze CORS headers and return a list of finding dicts."""
    findings: list[dict] = []

    origin = headers.get("access-control-allow-origin")
    credentials = headers.get("access-control-allow-credentials")
    methods = headers.get("access-control-allow-methods")
    max_age = headers.get("access-control-max-age")

    if origin is None:
        return findings

    allow_credentials = _truthy(credentials)

    # Wildcard origin is dangerous when credentials are allowed.
    if origin.strip() == "*":
        findings.append(
            cis_finding(
                "ARGUS-CORS-001",
                "Wildcard CORS origin",
                evidence=f"Access-Control-Allow-Origin: {origin}",
                severity="HIGH" if allow_credentials else "MEDIUM",
                impact=(
                    "Any origin may read the response. When credentials are "
                    "enabled this exposes authenticated resources cross-origin."
                ),
                recommendation=(
                    "Restrict Access-Control-Allow-Origin to a specific set of "
                    "trusted origins. Avoid '*' when credentials is true."
                ),
            )
        )
    elif allow_credentials and origin.strip() not in ("*", "null"):
        # Credentials combined with an explicit origin. If the origin is
        # reflected from the request (rather than a fixed allowlist entry)
        # this enables cross-origin credential theft; a scanner cannot
        # verify the allowlist, so it is reported as HIGH.
        findings.append(
            cis_finding(
                "ARGUS-CORS-002",
                "Credentials allowed for explicit origin",
                evidence=(
                    f"Access-Control-Allow-Origin: {origin}; "
                    f"Access-Control-Allow-Credentials: {credentials}"
                ),
                severity="HIGH",
                impact=(
                    "Credentials are allowed for a specific origin. If this "
                    "origin is reflected from the request rather than a fixed "
                    "allowlist, browsers will send cookies to any origin the "
                    "server echoes, enabling cross-origin credential theft."
                ),
                recommendation=(
                    "Only allow a fixed list of trusted origins together with "
                    "credentials and never reflect the request Origin header."
                ),
            )
        )

    # Reflect-of-origin is risky even when allow-list is used.
    if origin.strip() not in ("*", "null"):
        findings.append(
            cis_finding(
                "ARGUS-CORS-003",
                "Reflected or explicit CORS origin configured",
                evidence=f"Access-Control-Allow-Origin: {origin}",
                severity="LOW",
                impact=(
                    "The origin value is either reflected from the request or "
                    "statically configured; verify it cannot be attacker "
                    "controlled."
                ),
                recommendation=(
                    "Ensure the allowed origin is a fixed whitelist rather than "
                    "reflecting the request Origin header."
                ),
            )
        )

    if origin.strip() == "null":
        findings.append(
            cis_finding(
                "ARGUS-CORS-004",
                "Null CORS origin allowed",
                evidence="Access-Control-Allow-Origin: null",
                severity="MEDIUM",
                impact=(
                    "The literal 'null' origin can be produced from sandboxed "
                    "pages and file:// contexts, enabling cross-origin access "
                    "from unexpected sources."
                ),
                recommendation="Remove the 'null' origin from the allow list.",
            )
        )

    if methods:
        dangerous = [
            m for m in methods.split(",") if m.strip().upper() in ("TRACE", "CONNECT")
        ]
        if dangerous:
            findings.append(
                cis_finding(
                    "ARGUS-CORS-005",
                    "Dangerous CORS method allowed",
                    evidence=f"Access-Control-Allow-Methods: {methods}",
                    severity="MEDIUM",
                    impact=(
                        "Allowing TRACE/CONNECT cross-origin can facilitate "
                        "cross-site tracing and other attacks."
                    ),
                    recommendation=(
                        "Restrict allowed methods to those actually used, "
                        "excluding TRACE and CONNECT."
                    ),
                )
            )

    if max_age and max_age.strip().isdigit() and int(max_age.strip()) > 600:
        findings.append(
            cis_finding(
                "ARGUS-CORS-006",
                "Long CORS preflight cache",
                evidence=f"Access-Control-Max-Age: {max_age}",
                severity="LOW",
                impact=(
                    "A very long preflight cache can delay enforcement of "
                    "tightened server policies."
                ),
                recommendation="Keep Access-Control-Max-Age modest (<=600).",
            )
        )

    return findings


def _truthy(value: str | None) -> bool:
    return value is not None and value.strip().lower() == "true"


def cis_finding(
    rule_id: str,
    title: str,
    evidence: str,
    severity: str,
    impact: str,
    recommendation: str,
) -> dict:
    """Build a CORS finding dict with category metadata and references."""
    return make_finding(
        id=rule_id,
        category="CORS",
        severity=severity,
        title=title,
        description=impact,
        evidence=evidence,
        impact=impact,
        recommendation=recommendation,
        risk=impact,
        references=references_for("cors"),
    ).to_dict()
