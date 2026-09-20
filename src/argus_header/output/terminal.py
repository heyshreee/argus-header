"""Rich terminal formatting for score 2.0, findings and CI output."""

from __future__ import annotations

from rich.console import Console
from rich.panel import Panel

from argus_header.models.report import CATEGORIES

console = Console()

GRADE_COLORS = {
    "A+": "green",
    "A": "green",
    "B": "green",
    "C": "yellow",
    "D": "yellow",
    "F": "red",
}

SEVERITY_COLORS = {
    "CRITICAL": "bold red",
    "HIGH": "red",
    "MEDIUM": "yellow",
    "LOW": "blue",
}

SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]


def _bar(value: int, total: int, width: int = 10) -> str:
    filled = round((value / total) * width) if total else 0
    return "#" * filled + "-" * (width - filled)


def _grade_bracket(grade: str) -> str:
    color = GRADE_COLORS.get(grade, "white")
    return f"[{color}][{grade}][/{color}]"


def print_score_breakdown(score) -> None:
    """Render the ARGUS SECURITY SCORE panel with category breakdown."""
    lines = []
    lines.append(f"Overall       {score.score:>3}/100   {_grade_bracket(score.grade)}")
    lines.append("")

    categories = score.categories
    for category in CATEGORIES:
        cat_score = categories.get(category, 0)
        max_points = score.weights.get(category, 0)
        lines.append(f"{category:<12} {cat_score:>3}/{max_points}")

    lines.append("")
    breakdown = score.breakdown or {}
    lines.append(
        "Critical:  {}   High:  {}   Medium:  {}   Low:  {}".format(
            breakdown.get("CRITICAL", 0),
            breakdown.get("HIGH", 0),
            breakdown.get("MEDIUM", 0),
            breakdown.get("LOW", 0),
        )
    )

    color = GRADE_COLORS.get(score.grade, "white")
    risk_color = SEVERITY_COLORS.get(score.risk_level, "bold")
    lines.append("")
    lines.append(
        f"Grade: [{color}]{score.grade}[/{color}]   "
        f"Risk: [{risk_color}]{score.risk_level}[/{risk_color}]"
    )

    console.print(Panel("\n".join(lines), title="ARGUS SECURITY SCORE", expand=False))


def print_findings_professional(findings: list[dict]) -> None:
    """Render findings using the professional [SEVERITY] ID format."""
    if not findings:
        console.print(
            "[bold green][OK] No security misconfigurations detected.[/bold green]"
        )
        return

    ordered = sorted(
        findings,
        key=lambda f: SEVERITY_ORDER.index(
            f.get("severity", "LOW").upper()
            if f.get("severity", "LOW").upper() in SEVERITY_ORDER
            else "LOW"
        ),
    )

    for f in ordered:
        severity = str(f.get("severity", "LOW")).upper()
        color = SEVERITY_COLORS.get(severity, "bold")
        rule_id = f.get("id", "ARGUS-UNKNOWN")
        title = f.get("title") or f.get("issue", "Finding")

        console.print(
            Panel(
                f"[bold]{title}[/bold]\n\n"
                f"[bold]Evidence:[/bold] {f.get('evidence', 'N/A')}\n\n"
                f"[bold]Impact:[/bold] {f.get('impact') or f.get('risk', 'N/A')}\n\n"
                f"[bold]Recommendation:[/bold] {f.get('recommendation') or f.get('fix', 'N/A')}"
                + _references_block(f),
                title=f"[{color}]{severity}[/{color}] {rule_id}",
                border_style="dim",
                expand=False,
            )
        )
        console.print()


def _references_block(f: dict) -> str:
    refs = f.get("references") or []
    if not refs:
        return ""
    return "\n\n[bold]References:[/bold]\n" + "\n".join(f"  - {r}" for r in refs)


def print_ci_result(score, target: str, fail_reason: str | None) -> None:
    """Render the ARGUS CI SECURITY CHECK result block."""
    color = GRADE_COLORS.get(score.grade, "white")
    passed = fail_reason is None
    status = "[bold green]PASS[/bold green]" if passed else "[bold red]FAIL[/bold red]"

    lines = [
        f"Target: {target}",
        "",
        f"Score: {score.score}/100",
        f"Grade: [{color}]{score.grade}[/{color}]",
    ]
    breakdown = score.breakdown or {}
    lines.append("")
    for sev in SEVERITY_ORDER:
        c = SEVERITY_COLORS.get(sev, "bold")
        lines.append(f"{sev} findings: [{c}]{breakdown.get(sev, 0)}[/{c}]")

    lines.append("")
    lines.append(f"Result: {status}")

    if fail_reason:
        lines.append("")
        lines.append(f"[bold red]Reason:[/bold red] {fail_reason}")

    console.print(
        Panel("\n".join(lines), title="ARGUS CI SECURITY CHECK", expand=False)
    )


def _item_label(item) -> str:
    if isinstance(item, dict):
        title = item.get("title") or item.get("issue") or item.get("id", "")
        rule_id = item.get("id", "")
        return f"{rule_id} - {title}" if rule_id else str(title)
    return str(item)


def print_diff_result(diff) -> None:
    """Render the ARGUS SECURITY DIFF panel."""
    lines = []
    lines.append("Score")
    lines.append(f"  Before: {diff.get('score_before', 'N/A')}")
    lines.append(f"  After:  {diff.get('score_after', 'N/A')}")
    lines.append(f"  Change: {diff.get('score_delta', 0):+d}")
    lines.append("")

    fixed = diff.get("fixed", [])
    new = diff.get("new", [])
    if fixed:
        lines.append("FIXED")
        for item in fixed:
            lines.append(f"  [FIXED] {_item_label(item)}")
    if new:
        lines.append("NEW")
        for item in new:
            lines.append(f"  [NEW] {_item_label(item)}")

    posture = diff.get("posture", "UNCHANGED")
    pcolor = (
        "green"
        if posture == "IMPROVED"
        else "red" if posture == "DEGRADED" else "yellow"
    )
    lines.append("")
    lines.append(f"Security posture: [{pcolor}]{posture}[/{pcolor}]")

    console.print(Panel("\n".join(lines), title="ARGUS SECURITY DIFF", expand=False))
