"""Report and score data models for the v0.8 security engine."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

# Categories that make up the aggregate security score.
CATEGORIES = [
    "Content",
    "Transport",
    "Browser",
    "Isolation",
    "Cookies",
]


@dataclass
class ScoreData:
    """Security score 2.0 result.

    In addition to the aggregate 0-100 score and letter grade (which the
    v0.7 scorer already produced), ScoreData carries per-category scores,
    a severity-based deduction breakdown and a configurable weight map.
    """

    score: int
    grade: str
    risk_level: str
    penalty: int
    total_findings: int
    categories: dict[str, int] = field(default_factory=dict)
    max_per_category: int = 0  # points available per-category contribution
    breakdown: dict[str, int] = field(
        default_factory=lambda: {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    )
    weights: dict[str, float] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Serialize to the canonical report score block."""
        return {
            "value": self.score,
            "grade": self.grade,
            "risk_level": self.risk_level,
            "penalty": self.penalty,
            "total_findings": self.total_findings,
            "categories": dict(self.categories),
            "max_per_category": self.max_per_category,
            "breakdown": dict(self.breakdown),
            "weights": dict(self.weights),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ScoreData:
        return cls(
            score=int(data.get("value", data.get("score", 0))),
            grade=str(data.get("grade", "F")),
            risk_level=str(data.get("risk_level", "LOW")),
            penalty=int(data.get("penalty", 0)),
            total_findings=int(data.get("total_findings", 0)),
            categories=dict(data.get("categories", {})),
            max_per_category=int(data.get("max_per_category", 0)),
            breakdown=dict(data.get("breakdown", {})),
            weights=dict(data.get("weights", {})),
        )
