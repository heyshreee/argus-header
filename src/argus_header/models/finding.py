"""Structured security finding model.

Each finding carries a stable rule ID, a severity, a category, a title,
a description, supporting evidence, a security impact statement, a
recommendation and (where applicable) security references.

The analyzer rules are the single source of truth for detection; this
model only describes the shape every finding must satisfy.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any
from uuid import uuid4


@dataclass
class Finding:
    """A single security misconfiguration detected during a scan.

    ``issue`` and ``fix`` are retained as aliases of ``title`` and
    ``recommendation`` so that v0.8 structured findings remain backward
    compatible with the v0.7 report schema and existing consumer code.
    """

    id: str
    category: str
    severity: str
    title: str
    description: str = ""
    evidence: str = ""
    impact: str = ""
    recommendation: str = ""
    references: list[str] = field(default_factory=list)
    risk: str = ""
    issue: str = ""
    fix: str = ""
    _uid: str = field(default_factory=lambda: uuid4().hex[:8], repr=False)

    def __post_init__(self) -> None:
        if not self.issue:
            self.issue = self.title
        if not self.fix:
            self.fix = self.recommendation

    def to_dict(self) -> dict[str, Any]:
        """Serialize the finding to the canonical report dictionary,
        preserving the v0.7 fields and adding the v0.8 structured fields.
        """
        return {
            "id": self.id,
            "category": self.category,
            "severity": self.severity,
            "title": self.title,
            "description": self.description,
            "evidence": self.evidence,
            "impact": self.impact,
            "recommendation": self.recommendation,
            "references": list(self.references),
            "risk": self.risk or self.impact,
            "issue": self.issue,
            "fix": self.fix,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Finding:
        """Rebuild a Finding from a canonical report dictionary.

        Used when loading prior scan results for comparison mode where
        only a subset of fields may be present.
        """
        return cls(
            id=str(data.get("id", "UNKNOWN")),
            category=str(data.get("category", "General")),
            severity=str(data.get("severity", "LOW")),
            title=str(data.get("title", data.get("issue", "Unknown issue"))),
            description=str(data.get("description", "")),
            evidence=str(data.get("evidence", "")),
            impact=str(data.get("impact", "")),
            recommendation=str(data.get("recommendation", data.get("fix", ""))),
            references=list(data.get("references", [])),
            risk=str(data.get("risk", "")),
            issue=str(data.get("issue", "")),
            fix=str(data.get("fix", "")),
        )
