"""HTML report renderer for Argus Header."""

from html import escape
from pathlib import Path


def render_html(report: dict) -> str:
    """Render a canonical report dictionary as standalone HTML."""

    tool = report["tool"]
    scan = report["scan"]
    score = report["score"]
    summary = report["summary"]
    findings = report.get("findings", [])
    headers = report.get("headers", {})

    score_class = score["grade"].lower()

    finding_rows = []

    for finding in findings:
        severity = escape(str(finding.get("severity", "UNKNOWN")))
        issue = escape(str(finding.get("issue", "Unknown issue")))
        rule_id = escape(str(finding.get("id", "N/A")))
        category = escape(str(finding.get("category", "N/A")))
        risk = escape(str(finding.get("risk", "N/A")))
        fix = escape(str(finding.get("fix", "N/A")))

        finding_rows.append(
            f"""
            <article class="finding">
                <div class="finding-header">
                    <span class="severity severity-{severity.lower()}">
                        {severity}
                    </span>
                    <span class="rule-id">{rule_id}</span>
                </div>

                <h3>{issue}</h3>

                <p><strong>Category:</strong> {category}</p>
                <p><strong>Risk:</strong> {risk}</p>
                <p><strong>Fix:</strong> {fix}</p>
            </article>
            """
        )

    if not finding_rows:
        findings_html = """
        <div class="clean">
            ✓ No significant security issues found.
        </div>
        """
    else:
        findings_html = "\n".join(finding_rows)

    header_rows = []

    for name, value in headers.items():
        header_rows.append(
            f"""
            <tr>
                <td>{escape(str(name))}</td>
                <td>{escape(str(value))}</td>
            </tr>
            """
        )

    headers_html = "\n".join(header_rows)

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">

    <title>
        {escape(tool["name"])} Security Report
    </title>

    <style>
        :root {{
            --bg: #0b0f14;
            --panel: #111820;
            --border: #26313d;
            --text: #e8edf2;
            --muted: #98a6b5;
            --high: #ef4444;
            --medium: #f59e0b;
            --low: #3b82f6;
            --success: #22c55e;
        }}

        * {{
            box-sizing: border-box;
        }}

        body {{
            margin: 0;
            background: var(--bg);
            color: var(--text);
            font-family:
                Inter,
                ui-sans-serif,
                system-ui,
                -apple-system,
                sans-serif;
            line-height: 1.6;
        }}

        .container {{
            width: min(1100px, calc(100% - 32px));
            margin: 0 auto;
            padding: 40px 0 60px;
        }}

        h1 {{
            margin-bottom: 8px;
        }}

        h2 {{
            margin-top: 36px;
        }}

        .muted {{
            color: var(--muted);
        }}

        .panel {{
            background: var(--panel);
            border: 1px solid var(--border);
            border-radius: 14px;
            padding: 24px;
            margin-top: 20px;
        }}

        .score {{
            display: flex;
            align-items: center;
            gap: 24px;
            flex-wrap: wrap;
        }}

        .score-number {{
            font-size: 48px;
            font-weight: 800;
        }}

        .grade {{
            font-size: 32px;
            font-weight: 800;
        }}

        .grade-a {{ color: var(--success); }}
        .grade-b {{ color: var(--success); }}
        .grade-c {{ color: var(--medium); }}
        .grade-d {{ color: var(--medium); }}
        .grade-f {{ color: var(--high); }}

        .summary-grid {{
            display: grid;
            grid-template-columns: repeat(4, 1fr);
            gap: 12px;
        }}

        .summary-card {{
            background: var(--panel);
            border: 1px solid var(--border);
            border-radius: 12px;
            padding: 18px;
        }}

        .summary-value {{
            font-size: 26px;
            font-weight: 700;
        }}

        .summary-label {{
            color: var(--muted);
            font-size: 14px;
        }}

        .finding {{
            background: var(--panel);
            border: 1px solid var(--border);
            border-radius: 12px;
            padding: 20px;
            margin: 12px 0;
        }}

        .finding-header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            gap: 12px;
        }}

        .severity {{
            font-size: 12px;
            font-weight: 800;
            border-radius: 999px;
            padding: 4px 10px;
        }}

        .severity-high {{
            background: rgba(239, 68, 68, .15);
            color: #f87171;
        }}

        .severity-medium {{
            background: rgba(245, 158, 11, .15);
            color: #fbbf24;
        }}

        .severity-low {{
            background: rgba(59, 130, 246, .15);
            color: #60a5fa;
        }}

        .rule-id {{
            color: var(--muted);
            font-family: monospace;
        }}

        .clean {{
            border: 1px solid rgba(34, 197, 94, .35);
            background: rgba(34, 197, 94, .08);
            color: #86efac;
            border-radius: 12px;
            padding: 20px;
        }}

        table {{
            width: 100%;
            border-collapse: collapse;
            margin-top: 12px;
        }}

        th,
        td {{
            text-align: left;
            vertical-align: top;
            padding: 12px;
            border-bottom: 1px solid var(--border);
            word-break: break-word;
        }}

        th {{
            color: var(--muted);
        }}

        code {{
            font-family: monospace;
        }}

        footer {{
            margin-top: 40px;
            color: var(--muted);
            font-size: 13px;
        }}

        @media (max-width: 700px) {{
            .summary-grid {{
                grid-template-columns: repeat(2, 1fr);
            }}
        }}
    </style>
</head>

<body>
    <main class="container">

        <header>
            <h1>{escape(tool["name"])} Security Report</h1>
            <p class="muted">
                Generated by {escape(tool["name"])}
                {escape(tool["version"])}
            </p>
        </header>

        <section class="panel">
            <h2>Scan Information</h2>

            <p>
                <strong>Target:</strong>
                <code>{escape(str(scan["target"]))}</code>
            </p>

            <p>
                <strong>Final URL:</strong>
                <code>
                    {escape(str(scan.get("final_url", scan["target"])))}
                </code>
            </p>

            <p>
                <strong>Status:</strong>
                {escape(str(scan.get("status", "N/A")))}
            </p>

            <p>
                <strong>Method:</strong>
                {escape(str(scan.get("method", "GET")))}
            </p>

            <p>
                <strong>Timestamp:</strong>
                {escape(str(scan.get("timestamp", "N/A")))}
            </p>

            <p>
                <strong>Duration:</strong>
                {float(scan.get("duration_seconds", 0)):.4f}s
            </p>
        </section>

        <section class="panel">
            <h2>Security Score</h2>

            <div class="score">
                <div class="score-number">
                    {score["value"]}/100
                </div>

                <div class="grade grade-{score_class}">
                    Grade {escape(str(score["grade"]))}
                </div>

                <div>
                    <strong>Risk:</strong>
                    {escape(str(score["risk_level"]))}
                    <br>
                    <strong>Penalty:</strong>
                    {score["penalty"]}
                </div>
            </div>
        </section>

        <section>
            <h2>Findings Summary</h2>

            <div class="summary-grid">
                <div class="summary-card">
                    <div class="summary-value">
                        {summary["total_findings"]}
                    </div>
                    <div class="summary-label">Total</div>
                </div>

                <div class="summary-card">
                    <div class="summary-value">
                        {summary["high"]}
                    </div>
                    <div class="summary-label">High</div>
                </div>

                <div class="summary-card">
                    <div class="summary-value">
                        {summary["medium"]}
                    </div>
                    <div class="summary-label">Medium</div>
                </div>

                <div class="summary-card">
                    <div class="summary-value">
                        {summary["low"]}
                    </div>
                    <div class="summary-label">Low</div>
                </div>
            </div>
        </section>

        <section>
            <h2>Findings</h2>
            {findings_html}
        </section>

        <section class="panel">
            <h2>Response Headers</h2>

            <table>
                <thead>
                    <tr>
                        <th>Header</th>
                        <th>Value</th>
                    </tr>
                </thead>

                <tbody>
                    {headers_html}
                </tbody>
            </table>
        </section>

        <footer>
            Argus Header {escape(str(tool["version"]))}
        </footer>

    </main>
</body>
</html>
"""


def save_html(report: dict, filepath: str) -> None:
    """Render and save an HTML report."""

    content = render_html(report)

    Path(filepath).write_text(
        content,
        encoding="utf-8",
    )
