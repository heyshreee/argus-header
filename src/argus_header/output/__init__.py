"""Output rendering package for Argus Header v0.8.

Contains terminal, JSON, SARIF and cyberpunk-HTML report renderers.
"""

from .html_report import render_html, save_html
from .json_report import (
    build_report,
    load_report,
    render_json,
    save_report,
)
from .sarif import build_sarif, render_sarif, save_sarif
from .terminal import (
    print_ci_result,
    print_diff_result,
    print_findings_professional,
    print_score_breakdown,
)

__all__ = [
    "build_report",
    "build_sarif",
    "load_report",
    "print_ci_result",
    "print_diff_result",
    "print_findings_professional",
    "print_score_breakdown",
    "render_html",
    "render_json",
    "render_sarif",
    "save_html",
    "save_report",
    "save_sarif",
]
