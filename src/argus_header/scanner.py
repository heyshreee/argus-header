"""High-level scan pipeline for v0.8.

Runs the full analysis pipeline for a single target, producing both the
deep structured findings and the Score 2.0 result, wrapped in a canonical
v0.8 report.

    HTTP Response
          |
          v
    fetch_headers -> deep rules engine -> scoring -> v0.8 report
"""

from __future__ import annotations

import time
import uuid
from datetime import datetime, timezone
from typing import Any

from argus_header.engine.rules import run_rules
from argus_header.engine.scoring import calculate_score_2
from argus_header.models.configuration import Configuration
from argus_header.output.json_report import build_report
from argus_header.requester import fetch_headers


def scan_target(
    target: str,
    method: str = "GET",
    follow_redirects: bool = True,
    timeout: int = 10,
    config: Configuration | None = None,
) -> dict[str, Any]:
    """Perform a full v0.8 scan of a target URL.

    Returns the canonical v0.8 report dictionary.
    """
    method = method or "GET"
    timeout = timeout or 10
    if config is not None:
        method = config.method or method
        timeout = config.timeout or timeout
        follow_redirects = (
            config.redirects if "redirects" in _cfg_fields(config) else follow_redirects
        )

    start = time.perf_counter()
    response_data = fetch_headers(
        target,
        method=method,
        follow_redirects=follow_redirects,
        timeout=timeout,
    )
    duration = time.perf_counter() - start

    if not response_data.get("success"):
        return {
            "schema_version": "0.8",
            "tool": {"name": "Argus Header", "version": _version()},
            "scan": {
                "target": target,
                "status": None,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "duration_seconds": round(duration, 4),
                "method": method,
            },
            "score": {
                "value": 0,
                "grade": "F",
                "risk_level": "LOW",
                "penalty": 0,
                "categories": {},
                "breakdown": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0},
            },
            "summary": {
                "total_findings": 0,
                "critical": 0,
                "high": 0,
                "medium": 0,
                "low": 0,
            },
            "headers": {},
            "findings": [],
            "error": response_data.get("error"),
        }

    headers = response_data.get("headers", {})
    findings = run_rules(headers, config=config)
    score = calculate_score_2(findings)

    report = build_report(
        target=target,
        headers=headers,
        findings=findings,
        score=score,
        scan_id=uuid.uuid4().hex[:8],
        method=method,
        duration=duration,
        status=response_data.get("status_code"),
        final_url=response_data.get("url"),
        config=config,
    )

    # Attach the response wrapper for rich rendering (keeps parity with v0.7
    # scan dicts where the reporter consumes a response block).
    report["_response"] = {
        "success": True,
        "url": response_data.get("url"),
        "status_code": response_data.get("status_code"),
        "headers": dict(headers),
        "http_version": response_data.get("http_version"),
    }
    return report


def _cfg_fields(config: Configuration) -> set[str]:
    """Return the attribute names actually set on a configuration object."""
    return set(vars(config).keys())


def _version() -> str:
    from argus_header import __version__

    return __version__
