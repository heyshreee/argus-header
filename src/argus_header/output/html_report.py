"""Cyberpunk-styled HTML security report renderer for v0.8.

Self-contained single-file HTML with an embedded terminal/cyberpunk
visual theme, big score readout, category bars and finding cards.
"""

from __future__ import annotations

from collections.abc import Mapping
from html import escape
from pathlib import Path
from typing import Any

from argus_header.models.report import CATEGORIES


def render_html(report: Mapping[str, Any]) -> str:
    """Render a v0.8 report dictionary as standalone HTML."""
    tool = report.get("tool", {})
    scan = report.get("scan", {})
    score = report.get("score", {})
    summary = report.get("summary", {})
    findings = report.get("findings", [])
    headers = report.get("headers", {})

    score_value = int(score.get("value", 0))
    grade = str(score.get("grade", "F"))
    categories = score.get("categories", {})
    weights = score.get("weights", {})

    grade_color = {
        "A+": "#22c55e",
        "A": "#22c55e",
        "B": "#4ade80",
        "C": "#facc15",
        "D": "#fb923c",
        "F": "#ef4444",
    }.get(grade, "#e8edf2")

    category_rows = []
    for cat in CATEGORIES:
        cat_score = int(categories.get(cat, 0))
        max_points = int(weights.get(cat, 25) or 25)
        pct = round((cat_score / max_points) * 100) if max_points else 0
        category_rows.append(f"""
            <div class="cat-row">
                <span class="cat-name">{escape(cat)}</span>
                <span class="cat-bar">
                    <span class="cat-fill" style="width:{pct}%"></span>
                </span>
                <span class="cat-val">{cat_score}/{max_points}</span>
            </div>
            """)

    severity_meta = {
        "CRITICAL": ("#ef4444", "#7f1d1d"),
        "HIGH": ("#ff6b6b", "#7f1d1d"),
        "MEDIUM": ("#facc15", "#713f12"),
        "LOW": ("#38bdf8", "#0c4a6e"),
    }

    finding_cards = []
    sev_order = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
    ordered_findings = sorted(
        findings,
        key=lambda f: (
            sev_order.index(f.get("severity", "LOW").upper())
            if f.get("severity", "LOW").upper() in sev_order
            else 9
        ),
    )
    for f in ordered_findings:
        sev = str(f.get("severity", "LOW")).upper()
        fg, bg = severity_meta.get(sev, ("#e8edf2", "#374151"))
        refs = f.get("references") or []
        ref_html = "".join(
            f'<li><a href="{escape(str(r))}" target="_blank" rel="noopener">{escape(str(r))}</a></li>'
            for r in refs
        )
        finding_cards.append(f"""
            <div class="finding-card" style="border-left-color:{fg}">
                <div class="finding-head">
                    <span class="sev-badge" style="background:{bg};color:{fg}">{escape(sev)}</span>
                    <span class="rule-id">{escape(str(f.get('id', 'ARGUS-UNKNOWN')))}</span>
                </div>
                <h3>{escape(str(f.get('title') or f.get('issue', 'Finding')))}</h3>
                <p class="field"><span>Evidence</span>{escape(str(f.get('evidence', 'N/A')))}</p>
                <p class="field"><span>Impact</span>{escape(str(f.get('impact') or f.get('risk', 'N/A')))}</p>
                <p class="field"><span>Recommendation</span>{escape(str(f.get('recommendation') or f.get('fix', 'N/A')))}</p>
                {('<div class="refs"><strong>References</strong><ul>' + ref_html + '</ul></div>') if ref_html else ''}
            </div>
            """)

    header_rows = "".join(
        f"<tr><td>{escape(str(k))}</td><td>{escape(str(v))}</td></tr>"
        for k, v in headers.items()
    )

    summary_meta = [
        ("Critical", summary.get("critical", 0), "#ef4444"),
        ("High", summary.get("high", 0), "#ff6b6b"),
        ("Medium", summary.get("medium", 0), "#facc15"),
        ("Low", summary.get("low", 0), "#38bdf8"),
    ]
    summary_cards = "".join(f"""
        <div class="stat-card">
            <div class="stat-value" style="color:{c}">{v}</div>
            <div class="stat-label">{escape(name)}</div>
        </div>
        """ for name, v, c in summary_meta)

    category_html = (
        "".join(category_rows) if category_rows else "<p>No category data.</p>"
    )
    findings_html = (
        "".join(finding_cards)
        if finding_cards
        else '<div class="clean">✓ No security misconfigurations detected.</div>'
    )

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>{escape(str(tool.get('name', 'Argus Header')))} Security Assessment</title>
<style>
:root {{
    --bg: #05080c;
    --panel: #0b1220;
    --panel2: #0f172a;
    --border: #1e293b;
    --neon: #22d3ee;
    --text: #dbe7f3;
    --muted: #64748b;
}}
* {{ box-sizing: border-box; }}
body {{
    margin: 0; background: var(--bg); color: var(--text);
    font-family: 'Courier New', ui-monospace, monospace;
    line-height: 1.6;
}}
.scanlines::before {{
    content: ""; position: fixed; inset: 0; pointer-events: none;
    background: repeating-linear-gradient(0deg, rgba(0,0,0,.08) 0 1px, transparent 1px 3px);
}}
.wrap {{ max-width: 1080px; margin: 0 auto; padding: 40px 20px 80px; }}
h1 {{ color: var(--neon); text-transform: uppercase; letter-spacing: 3px; }}
.sub {{ color: var(--muted); }}
.panel {{ background: var(--panel); border:1px solid var(--border); border-radius:12px; padding:24px; margin-top:28px; }}
.panel h2 {{ color: var(--neon); text-transform: uppercase; letter-spacing:2px; font-size:15px; border-bottom:1px solid var(--border); padding-bottom:10px; }}
.score-hero {{ display:flex; align-items:center; gap:32px; flex-wrap:wrap; }}
.score-big {{ font-size:76px; font-weight:900; color: {grade_color}; text-shadow:0 0 24px {grade_color}44; }}
.grade-big {{ font-size:56px; font-weight:900; color:{grade_color}; }}
.summary-grid {{ display:grid; grid-template-columns:repeat(4,1fr); gap:14px; margin-top:12px; }}
.stat-card {{ background:var(--panel2); border:1px solid var(--border); border-radius:8px; padding:20px; text-align:center; }}
.stat-value {{ font-size:30px; font-weight:800; }}
.stat-label {{ color:var(--muted); font-size:13px; text-transform:uppercase; }}
.cat-row {{ display:flex; align-items:center; gap:14px; margin:10px 0; }}
.cat-name {{ width:110px; }}
.cat-bar {{ flex:1; height:16px; background:var(--panel2); border:1px solid var(--border); border-radius:4px; overflow:hidden; }}
.cat-fill {{ display:block; height:100%; background:linear-gradient(90deg,var(--neon),#a3e635); }}
.cat-val {{ width:80px; text-align:right; }}
.finding-card {{ background:var(--panel2); border:1px solid var(--border); border-left:4px solid var(--neon); border-radius:8px; padding:18px; margin:14px 0; }}
.finding-head {{ display:flex; justify-content:space-between; align-items:center; margin-bottom:8px; }}
.sev-badge {{ font-size:11px; font-weight:800; border-radius:4px; padding:3px 8px; text-transform:uppercase; }}
.rule-id {{ color:var(--muted); }}
.finding-card h3 {{ margin:4px 0 10px; }}
.field span {{ display:block; color:var(--neon); font-size:11px; text-transform:uppercase; margin-top:8px; }}
.refs {{ margin-top:12px; }}
.refs li {{ margin:2px 0; }}
.refs a {{ color:#7dd3fc; }}
table {{ width:100%; border-collapse:collapse; margin-top:12px; }}
th,td {{ text-align:left; vertical-align:top; padding:10px; border-bottom:1px solid var(--border); word-break:break-word; }}
th {{ color:var(--muted); }}
.clean {{ border:1px solid rgba(34,197,94,.4); color:#86efac; padding:16px; border-radius:8px; }}
footer {{ margin-top:40px; color:var(--muted); font-size:12px; }}
@media(max-width:700px) {{ .summary-grid {{ grid-template-columns:repeat(2,1fr); }} .score-big {{ font-size:52px; }} }}
</style>
</head>
<body class="scanlines">
<main class="wrap">
    <header>
        <h1>Argus-Header</h1>
        <div class="sub">SECURITY ASSESSMENT • {escape(str(tool.get('version', '')))}</div>
    </header>

    <section class="panel">
        <h2>Scan Info</h2>
        <p>Target: <code>{escape(str(scan.get('target', 'N/A')))}</code></p>
        <p>Status: <code>{escape(str(scan.get('status', 'N/A')))}</code> • Method: <code>{escape(str(scan.get('method', 'GET')))}</code></p>
        <p>Timestamp: <code>{escape(str(scan.get('timestamp', 'N/A')))}</code> • Duration: <code>{float(scan.get('duration_seconds', 0)):.2f}s</code></p>
    </section>

    <section class="panel">
        <h2>Security Score</h2>
        <div class="score-hero">
            <div>
                <div class="score-big">{score_value}</div>
                <div style="color:var(--muted)">/ 100</div>
            </div>
            <div class="grade-big">{escape(grade)}</div>
        </div>
    </section>

    <section class="panel">
        <h2>Findings Summary</h2>
        <div class="summary-grid">{summary_cards}</div>
    </section>

    <section class="panel">
        <h2>Security Headers</h2>
        {category_html}
    </section>

    <section>
        <h2 style="color:var(--neon);text-transform:uppercase;letter-spacing:2px;">Findings</h2>
        {findings_html}
    </section>

    <section class="panel">
        <h2>Response Headers</h2>
        <table><thead><tr><th>Header</th><th>Value</th></tr></thead>
        <tbody>{header_rows}</tbody></table>
    </section>

    <footer>Generated by {escape(str(tool.get('name', 'Argus Header')))} {escape(str(tool.get('version', '')))}</footer>
</main>
</body>
</html>
"""


def save_html(report: Mapping[str, Any], filepath: str) -> None:
    """Render and save the HTML report."""
    Path(filepath).write_text(render_html(report), encoding="utf-8")
