"""Cache-Control and caching security analysis.

Inspects Cache-Control and Pragma for missing or permissive caching that
could allow sensitive responses to be cached and replayed.
"""

from __future__ import annotations

from collections.abc import Mapping

from argus_header.engine.findings import make_finding
from argus_header.engine.references import references_for


def analyze_cache(headers: Mapping[str, str]) -> list[dict]:
    """Analyze caching headers and return finding dicts."""
    findings: list[dict] = []

    cache_control = headers.get("cache-control")
    if cache_control is None:
        findings.append(
            cache_finding(
                "ARGUS-CACHE-001",
                "Missing Cache-Control header",
                "LOW",
                "Cache-Control header absent",
                (
                    "Without explicit caching policy, shared and private caches "
                    "may apply heuristics that leak/age the response."
                ),
                "Define an appropriate Cache-Control policy for the content.",
            )
        )
    else:
        directives = [d.strip().lower() for d in cache_control.split(",")]
        if "no-store" not in directives:
            findings.append(
                cache_finding(
                    "ARGUS-CACHE-002",
                    "Cache-Control allows sensitive content caching",
                    "MEDIUM",
                    cache_control,
                    (
                        "Absence of no-store means the response may be cached "
                        "and served to later visitors."
                    ),
                    "Use no-store (and no-cache) for sensitive data.",
                )
            )

        if "public" in directives and not _has_safety(directives):
            findings.append(
                cache_finding(
                    "ARGUS-CACHE-003",
                    "Cache-Control is public without safety directives",
                    "MEDIUM",
                    cache_control,
                    (
                        "A public cache policy without no-cache/no-store can "
                        "cache authenticated responses."
                    ),
                    "Add no-cache/no-store or remove public.",
                )
            )

    pragma = headers.get("pragma")
    if pragma is None or pragma.lower() != "no-cache":
        pass  # Pragma is a legacy fallback; not penalised on its own.

    return findings


def _has_safety(directives: list[str]) -> bool:
    return any(d in ("no-store", "no-cache", "private") for d in directives)


def cache_finding(
    rule_id: str,
    title: str,
    severity: str,
    evidence: str,
    impact: str,
    recommendation: str,
) -> dict:
    return make_finding(
        id=rule_id,
        category="Cache",
        severity=severity,
        title=title,
        description=impact,
        evidence=evidence,
        impact=impact,
        recommendation=recommendation,
        risk=impact,
        references=references_for("cache"),
    ).to_dict()
