"""SARIF 2.1.0 report generation.

Enables findings to integrate with GitHub/GitLab code-scanning and other
SARIF-aware security tooling.
"""

from __future__ import annotations

import json
from collections.abc import Iterable, Mapping
from pathlib import Path
from typing import Any

SARIF_VERSION = "2.1.0"
SCHEMA = (
    "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/"
    "Schemas/sarif-schema-2.1.0.json"
)


def build_sarif(
    findings: Iterable[Mapping[str, Any]],
    target: str,
    tool_name: str = "Argus Header",
    rule_index: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    """Build a SARIF 2.1.0 document from findings.

    ``rule_index`` may map a rule id to a short description for the rules
    block; when omitted it is derived from each finding.
    """
    findings = list(findings)
    rules: dict[str, dict[str, Any]] = {}
    rule_map = rule_index or {}

    results = []
    for f in findings:
        rule_id = str(f.get("id", "ARGUS-UNKNOWN"))
        desc = rule_map.get(rule_id, str(f.get("title", "")))
        rules.setdefault(rule_id, {"id": rule_id, "shortDescription": {"text": desc}})

        results.append(
            {
                "ruleId": rule_id,
                "level": _sarif_level(f.get("severity", "LOW")),
                "message": {
                    "text": str(f.get("title", f.get("issue", rule_id))),
                },
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": target,
                            }
                        }
                    }
                ],
                "properties": {
                    "category": str(f.get("category", "")),
                    "evidence": str(f.get("evidence", "")),
                    "impact": str(f.get("impact", "")),
                    "recommendation": str(f.get("recommendation", "")),
                },
            }
        )

    return {
        "$schema": SCHEMA,
        "version": SARIF_VERSION,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": tool_name,
                        "informationUri": "https://github.com/heyshreee/argus-header",
                        "rules": list(rules.values()),
                    }
                },
                "results": results,
                "invocations": [
                    {
                        "executionSuccessful": True,
                        "commandLine": f"argus-header {target}",
                    }
                ],
            }
        ],
    }


def _sarif_level(severity: str) -> str:
    mapping = {
        "CRITICAL": "error",
        "HIGH": "error",
        "MEDIUM": "warning",
        "LOW": "note",
    }
    return mapping.get(str(severity).upper(), "warning")


def render_sarif(sarif: dict[str, Any]) -> str:
    """Serialize a SARIF document to a JSON string."""
    return json.dumps(sarif, indent=2)


def save_sarif(sarif: dict[str, Any], filepath: str) -> None:
    """Write a SARIF document to a file."""
    Path(filepath).write_text(render_sarif(sarif) + "\n", encoding="utf-8")
