"""CI/CD policy evaluation.

Determines whether a scan passes or fails a build gate based on the
configured severity threshold (--fail-on) and minimum score (--min-score).
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]

# Map a gate severity to the exclusive minimum severity index that triggers
# a failure. A finding whose index is < threshold fails the gate, so:
#   critical -> 1 (only CRITICAL fails)
#   high     -> 2 (CRITICAL, HIGH fail)
#   medium   -> 3 (CRITICAL, HIGH, MEDIUM fail)
#   low      -> 4 (any finding fails)
FAIL_ON_INDEX = {
    "critical": 1,
    "high": 2,
    "medium": 3,
    "low": 4,
    "none": 99,  # never fail on severity
}


class GateResult:
    """Result of evaluating a scan against a CI gate policy."""

    def __init__(self, passed: bool, reason: str | None):
        self.passed = passed
        self.reason = reason

    def __bool__(self) -> bool:
        return self.passed


def evaluate_gate(
    score: Any,
    findings: list[dict[str, Any]],
    fail_on: str = "high",
    minimum_score: int = 80,
) -> GateResult:
    """Evaluate whether a scan satisfies the configured gate.

    Fails when any finding is at or above the ``fail_on`` severity, or when
    the aggregate score is below ``minimum_score``.
    """
    fail_on = (fail_on or "high").lower()
    if fail_on not in FAIL_ON_INDEX:
        fail_on = "high"

    threshold = FAIL_ON_INDEX[fail_on]

    for finding in findings:
        severity = str(finding.get("severity", "LOW")).upper()
        if severity in SEVERITY_ORDER:
            idx = SEVERITY_ORDER.index(severity)
            if idx < threshold:
                return GateResult(
                    False,
                    f"{severity} severity finding detected (fail_on={fail_on}).",
                )

    score_value = _score_value(score)
    if score_value < minimum_score:
        return GateResult(
            False,
            f"Score {score_value} is below the minimum of {minimum_score}.",
        )

    return GateResult(True, None)


def _score_value(score: Any) -> int:
    if isinstance(score, Mapping):
        return int(score.get("value", score.get("score", 0)))
    return int(getattr(score, "score", getattr(score, "value", 0)))
