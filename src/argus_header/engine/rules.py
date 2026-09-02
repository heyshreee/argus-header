"""Security rules engine.

The rules engine orchestrates the deep header analyzers. Given a parsed
set of response headers and a configuration, it runs every enabled rule
family (CSP, CORS, Cookies, HSTS, Cache, Cross-Origin, Referrer,
Permissions) and collects the resulting structured findings.

Architecture:

    HTTP Response
          |
          v
    Header Normalization
          |
          v
    Security Rules Engine
          |-- CSP Rules
          |-- CORS Rules
          |-- Cookie Rules
          |-- HSTS Rules
          |-- Cache Rules
          |-- Cross-Origin Rules
          |-- Referrer Rules
          `-- Permissions Rules
          |
          v
    Finding Engine -> Risk + Recommendation
"""

from __future__ import annotations

import logging
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Callable

from argus_header.analyzers.base_headers import analyze_base_headers
from argus_header.analyzers.cache import analyze_cache
from argus_header.analyzers.cookies import analyze_cookies
from argus_header.analyzers.cors import analyze_cors
from argus_header.analyzers.cross_origin import analyze_cross_origin
from argus_header.analyzers.csp import analyze_csp
from argus_header.analyzers.hsts import analyze_hsts
from argus_header.analyzers.permissions import analyze_permissions
from argus_header.analyzers.referrer import analyze_referrer
from argus_header.engine.findings import as_dicts
from argus_header.models.configuration import Configuration, RulesConfig

logger = logging.getLogger(__name__)

AnalyzerFn = Callable[[dict[str, str]], list[dict]]


@dataclass
class Rule:
    """Registration entry for one deep-analysis rule family."""

    name: str
    key: str
    analyzer: AnalyzerFn
    description: str = ""


RULES: list[Rule] = [
    Rule("Content Security Policy", "csp", analyze_csp, "CSP directive analysis"),
    Rule("Cross-Origin Resource Sharing", "cors", analyze_cors, "CORS configuration"),
    Rule("Cookies", "cookies", analyze_cookies, "Cookie attribute security"),
    Rule("HTTP Strict Transport Security", "hsts", analyze_hsts, "HSTS configuration"),
    Rule("Cache Control", "cache", analyze_cache, "Cache header policy"),
    Rule(
        "Cross-Origin Policies", "cross_origin", analyze_cross_origin, "COOP/CORP/COEP"
    ),
    Rule("Referrer Policy", "referrer", analyze_referrer, "Referrer-Policy value"),
    Rule(
        "Permissions Policy", "permissions", analyze_permissions, "Permissions-Policy"
    ),
    Rule(
        "Base Security Headers",
        "base_headers",
        analyze_base_headers,
        "XFO, XCTO, Server/X-Powered-By leaks",
    ),
]


def _rule_enabled(rules: RulesConfig, key: str) -> bool:
    return bool(getattr(rules, key, True))


def run_rules(
    headers: Mapping[str, str],
    config: Configuration | None = None,
) -> list[dict]:
    """Run all enabled rule families against normalized headers.

    Returns a flattened list of finding dictionaries. When a configuration
    disables a rule family, those analyzers are skipped.
    """
    normalized = normalize_headers(headers)
    findings: list[dict] = []
    enabled = config.rules if config else RulesConfig()

    for rule in RULES:
        if not _rule_enabled(enabled, rule.key):
            continue
        try:
            findings.extend(as_dicts(rule.analyzer(dict(normalized))))
        except (KeyError, ValueError, TypeError, AttributeError, IndexError) as exc:
            logger.debug("Rule family %s failed: %s", rule.key, exc)
            continue

    return findings


def run_rule(
    key: str,
    headers: Mapping[str, str],
) -> list[dict]:
    """Run a single named rule family and return its findings."""
    normalized = normalize_headers(headers)
    for rule in RULES:
        if rule.key == key:
            return as_dicts(rule.analyzer(dict(normalized)))
    return []


def normalize_headers(headers: Mapping[str, str]) -> dict[str, str]:
    """Lowercase header names for case-insensitive analysis."""
    normalized: dict[str, str] = {}
    for name, value in headers.items():
        normalized[name.lower()] = value
    return normalized


__all__ = ["RULES", "Rule", "normalize_headers", "run_rule", "run_rules"]
