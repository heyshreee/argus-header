"""Content-Security-Policy deep analysis.

Moves beyond a simple presence check: parses the policy directives and
flags dangerous constructs such as wildcard sources, ``unsafe-inline``,
``unsafe-eval``, a missing default-src and frame-ancestors.
"""

from __future__ import annotations

from collections.abc import Mapping

from argus_header.engine.findings import make_finding
from argus_header.engine.references import references_for

CSP_HEADERS = ("content-security-policy", "content-security-policy-report-only")

DANGEROUS_KEYWORDS = (
    ("'unsafe-inline'", "unsafe-inline"),
    ("'unsafe-eval'", "unsafe-eval"),
    ("'*'", "wildcard source"),  # keyword token for a bare *
)

# Directive names whose sources matter for script-execution safety.
SCRIPT_DIRECTIVES = ("script-src", "default-src")


def _directives(policy: str) -> dict[str, str]:
    """Split a CSP policy into {directive: sources} preserving order."""
    result: dict[str, str] = {}
    for token in policy.split(";"):
        token = token.strip()
        if not token:
            continue
        parts = token.split(None, 1)
        name = parts[0].lower()
        sources = parts[1].strip() if len(parts) > 1 else ""
        result[name] = sources
    return result


def analyze_csp(headers: Mapping[str, str]) -> list[dict]:
    """Analyze CSP headers and return a list of finding dicts."""
    findings = []

    value = _csp_value(headers)
    if value is None:
        findings.append(
            make_finding(
                id="ARGUS-CSP-001",
                category="CSP",
                severity="HIGH",
                title="Missing Content Security Policy",
                description=(
                    "The response does not include a Content-Security-Policy "
                    "header, so the browser has no content restrictions."
                ),
                evidence="Content-Security-Policy header absent",
                impact=(
                    "Weakens protection against Cross-Site Scripting (XSS), "
                    "data injection and clickjacking."
                ),
                recommendation=(
                    "Define a Content-Security-Policy with a strict "
                    "default-src and script-src."
                ),
                references=references_for("csp"),
            ).to_dict()
        )
        return findings

    directives = _directives(value)
    return _analyze_directives(value, directives)


def _csp_value(headers: Mapping[str, str]) -> str | None:
    """Return the active policy, preferring CSP over report-only."""
    if "content-security-policy" in headers:
        return headers["content-security-policy"]
    if "content-security-policy-report-only" in headers:
        return headers["content-security-policy-report-only"]
    return None


def _analyze_directives(raw_policy: str, directives: dict[str, str]) -> list[dict]:
    findings = []

    # A policy that parses to no directives at all is effectively empty.
    if not directives:
        findings.append(
            finding_weak(
                "ARGUS-CSP-002",
                "Empty or invalid Content Security Policy",
                evidence=raw_policy,
                note=(
                    "The policy could not be parsed into any directives, so "
                    "the browser applies no restrictions."
                ),
            )
        )
        return findings

    if "default-src" not in directives:
        findings.append(
            finding_weak(
                "ARGUS-CSP-101",
                "Content Security Policy missing default-src",
                evidence="missing default-src directive",
                note=(
                    "Without a default-src fallback, many source lists are "
                    "open by default and each directive must be defined."
                ),
            )
        )

    for directive in ("script-src", "default-src", "object-src", "frame-src"):
        sources = directives.get(directive, "")
        for fragment in ("*", "'unsafe-inline'", "'unsafe-eval'", "http:"):
            if _source_present(sources, fragment):
                findings.append(
                    finding_weak(
                        _fragment_rule_id(directive, fragment),
                        "Dangerous source in CSP directive",
                        evidence=f"{directive} {sources}",
                        note=_fragment_note(directive, fragment),
                    )
                )

    if "frame-ancestors" not in directives:
        findings.append(
            finding_weak(
                "ARGUS-CSP-201",
                "Content Security Policy missing frame-ancestors",
                evidence="missing frame-ancestors directive",
                note=(
                    "frame-ancestors prevents clickjacking independently of "
                    "X-Frame-Options."
                ),
            )
        )

    return findings


def _source_present(sources: str, fragment: str) -> bool:
    if fragment == "*":
        return "*" in sources.split()
    return fragment in sources


def _fragment_rule_id(directive: str, fragment: str) -> str:
    mapping = {
        "script-src": {
            "*": "ARGUS-CSP-003",
            "'unsafe-inline'": "ARGUS-CSP-004",
            "'unsafe-eval'": "ARGUS-CSP-005",
            "http:": "ARGUS-CSP-006",
        },
        "default-src": {
            "*": "ARGUS-CSP-102",
            "'unsafe-inline'": "ARGUS-CSP-103",
            "'unsafe-eval'": "ARGUS-CSP-104",
        },
        "object-src": {
            "*": "ARGUS-CSP-104",
            "'unsafe-inline'": "ARGUS-CSP-104",
            "'unsafe-eval'": "ARGUS-CSP-104",
        },
        "frame-src": {
            "*": "ARGUS-CSP-201",
            "'unsafe-inline'": "ARGUS-CSP-201",
            "'unsafe-eval'": "ARGUS-CSP-201",
            "http:": "ARGUS-CSP-204",
        },
    }
    return mapping.get(directive, {}).get(fragment, "ARGUS-CSP-999")


def _fragment_note(directive: str, fragment: str) -> str:
    if fragment == "'unsafe-inline'":
        return (
            "inline script/style execution remains enabled, which defeats "
            "much of CSP's value against XSS."
        )
    if fragment == "'unsafe-eval'":
        return (
            "eval() and similar dynamic code execution remains allowed, "
            "enabling script injection attacks."
        )
    if fragment == "http:":
        return (
            "cleartext HTTP sources are permitted, allowing downgrade and "
            "man-in-the-middle tampering."
        )
    return (
        "a wildcard source permits loading resources from any origin, "
        "dramatically weakening the policy."
    )


def finding_weak(
    rule_id: str,
    title: str,
    evidence: str,
    note: str,
) -> dict:
    """Build a MEDIUM-severity weak-policy finding."""
    return make_finding(
        id=rule_id,
        category="CSP",
        severity="MEDIUM",
        title=title,
        description=note,
        evidence=evidence,
        impact=(
            "Reduces the effectiveness of the Content Security Policy in "
            "mitigating injection and cross-site scripting attacks."
        ),
        recommendation=(
            "Restrict CSP sources to trusted origins and avoid wildcard or "
            "unsafe keywords where possible."
        ),
        references=references_for("csp"),
    ).to_dict()
