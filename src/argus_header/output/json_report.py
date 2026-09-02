"""Machine-readable JSON report builder for v0.8 scans."""

from __future__ import annotations

import json
from collections.abc import Mapping
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

SCHEMA_VERSION = "0.8"


def build_report(
    target: str,
    headers: Mapping[str, str],
    findings: list[dict],
    score: Any,
    scan_id: str,
    method: str = "GET",
    duration: float = 0.0,
    status: int | None = None,
    final_url: str | None = None,
    config: Any = None,
) -> dict[str, Any]:
    """Build the canonical v0.8 report dictionary.

    ``score`` is expected to be a :class:`ScoreData` (or an object with a
    matching ``to_dict()``/attributes). Findings are dictionaries.
    """
    critical = sum(1 for f in findings if f.get("severity") == "CRITICAL")
    high = sum(1 for f in findings if f.get("severity") == "HIGH")
    medium = sum(1 for f in findings if f.get("severity") == "MEDIUM")
    low = sum(1 for f in findings if f.get("severity") == "LOW")

    score_block = (
        score.to_dict()
        if hasattr(score, "to_dict")
        else (
            dict(score)
            if isinstance(score, Mapping)
            else {
                "value": 0,
                "grade": "F",
                "risk_level": "LOW",
                "penalty": 0,
                "total_findings": len(findings),
                "categories": {},
                "breakdown": {
                    "CRITICAL": critical,
                    "HIGH": high,
                    "MEDIUM": medium,
                    "LOW": low,
                },
            }
        )
    )

    config_block = None
    if config is not None:
        config_block = {
            "policy": {
                "minimum_score": config.policy.minimum_score,
                "fail_on": config.policy.fail_on,
            },
            "rules": config.rules.to_mapping(),
        }

    return {
        "schema_version": SCHEMA_VERSION,
        "tool": {
            "name": "Argus Header",
            "version": _version(),
        },
        "scan": {
            "id": scan_id,
            "target": target,
            "final_url": final_url or target,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "duration_seconds": round(float(duration), 4),
            "method": method,
            "status": status,
        },
        "score": score_block,
        "summary": {
            "total_findings": len(findings),
            "critical": critical,
            "high": high,
            "medium": medium,
            "low": low,
        },
        "headers": {str(k): str(v) for k, v in headers.items()},
        "findings": findings,
        "config": config_block,
    }


def render_json(report: dict[str, Any]) -> str:
    """Serialize a report dictionary to a JSON string."""
    return json.dumps(report, indent=2)


def save_report(report: dict[str, Any], filepath: str) -> None:
    """Write a report dictionary to a JSON file."""
    Path(filepath).write_text(render_json(report) + "\n", encoding="utf-8")


def load_report(filepath: str) -> dict[str, Any]:
    """Load a previously generated JSON report for comparison mode."""
    return json.loads(Path(filepath).read_text(encoding="utf-8"))


def _version() -> str:
    from argus_header import __version__

    return __version__
