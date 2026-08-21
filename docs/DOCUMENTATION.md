# 🛡️ Argus Header — Complete Technical Documentation

> **Version:** 0.7.0 · **Language:** Python ≥ 3.9 · **License:** MIT
> **Author:** Sriram ( [@heyshreee](https://github.com/heyshreee) )

Argus Header is a fast, lightweight **HTTP security header analyzer**. It sends an HTTP request to one or more target URLs, inspects the response headers, and reports security misconfigurations, information leakage, CORS issues, and performance concerns — via a Rich CLI, a verbose report, a JSON export, a REST API, and a web dashboard.

---

## Table of Contents

1. [Overview](#1-overview)
2. [Architecture](#2-architecture)
3. [Data Flow](#3-data-flow)
4. [Core Data Structures](#4-core-data-structures)
5. [Module Reference](#5-module-reference)
6. [Detection Rules Catalog](#6-detection-rules-catalog)
7. [CLI Reference](#7-cli-reference)
8. [REST API Reference](#8-rest-api-reference)
9. [Web Dashboard (frontend/)](#9-web-dashboard-frontend)
10. [Installation](#10-installation)
11. [Usage Examples](#11-usage-examples)
12. [JSON Report Format](#12-json-report-format)
13. [Testing](#13-testing)
14. [Docker Deployment](#14-docker-deployment)
15. [Development Guide](#15-development-guide)
16. [Known Issues & Limitations](#16-known-issues--limitations)
17. [Roadmap](#17-roadmap)
18. [Security & Legal Disclaimer](#18-security--legal-disclaimer)

---

## 1. Overview

### Problem

Modern browsers enforce many protections through HTTP response headers (CSP, HSTS, X-Frame-Options…). Misconfigured or missing headers expose sites to XSS, clickjacking, MITM downgrade attacks, MIME-sniffing, and fingerprinting — but developers rarely notice because nothing visibly "breaks."

### Solution

Argus Header automates header auditing:

| Interface | Entry point | Audience |
|---|---|---|
| **CLI** | `argus-header <url>` | Developers / pentesters in terminals |
| **REST API** | `api.py` (FastAPI) | Integrations, automation |
| **Web UI** | `frontend/index.html` | Non-technical users |

### Key Capabilities (v0.7.0)

- GET & HEAD requests, configurable timeout
- Automatic redirect following (optional) with retry/backoff on transient failures
- Single or multiple targets, optional parallel scanning (`ThreadPoolExecutor`, 5 workers)
- Severity-ranked findings with risk explanation + concrete fix recommendation
- Stable rule IDs on every finding (`SEC-001`, `LEAK-002`, `COOKIE-003`, …)
- Security Score (0–100), Grade (A–F), risk level and penalty breakdown
- Cookie security analysis (Secure / HttpOnly / SameSite)
- Enhanced JSON reports with scan metadata and ISO timestamps
- Markdown report export (`--markdown`)
- HTML report export (`--html`, self-contained and XSS-escaped)
- `--verbose` deep-dive report (15 sections)
- URL normalization (`example.com` → `https://example.com`)

---

## 2. Architecture

The project is organized as three layers around a shared analysis core.

```text
┌─────────────────────────────────────────────────────────────┐
│                        PRESENTATION                          │
│                                                              │
│   CLI (src/argus_header/cli.py + reporter.py + verbose.py)   │
│   Web Dashboard (frontend/) ──► REST API (api.py, FastAPI)   │
└──────────────────────┬───────────────────────┬──────────────┘
                       │                       │
                       ▼                       ▼
┌─────────────────────────────────────────────────────────────┐
│                          ANALYSIS                            │
│                                                              │
│   analyzer.py      — rule engine producing findings[]        │
│   verbose.py       — detailed section renderers              │
│   schemas.py       — Pydantic models for the API             │
└──────────────────────┬──────────────────────────────────────┘
                       │
                       ▼
┌─────────────────────────────────────────────────────────────┐
│                         NETWORK                              │
│                                                              │
│   requester.py     — requests.Session + Retry(3, backoff=1)  │
│   utils.py         — normalize_url()                         │
└──────────────────────────────────────────────────────────────┘
```

### Repository Layout

```text
argus-header/
├── src/
│   └── argus_header/          # Installable package (PyPI: argus-header)
│       ├── __init__.py        # Exports __version__, APP_NAME
│       ├── __main__.py        # python -m argus_header entry point
│       ├── cli.py             # Argument parsing, banner, orchestration
│       ├── requester.py       # HTTP fetch engine (requests + retry)
│       ├── analyzer.py        # Security analysis rule engine (+ rule IDs)
│       ├── cookies.py         # Set-Cookie attribute analysis (v0.7)
│       ├── scorer.py          # Score / grade / risk engine (v0.7)
│       ├── reporter.py        # Rich output, canonical report, JSON export
│       ├── markdown.py        # Markdown report renderer (v0.7)
│       ├── html_report.py     # HTML report renderer (v0.7)
│       ├── verbose.py         # 15-section detailed report
│       ├── schemas.py         # Pydantic models for the API
│       └── utils.py           # URL normalization helper
├── api.py                     # FastAPI wrapper (GET/POST /analyze)
├── main.py                    # Legacy standalone runner (report/ dir output)
├── frontend/                  # Vanilla JS dashboard (Tailwind CDN)
│   ├── index.html
│   ├── script.js
│   └── style.css
├── tests/                     # pytest suites
├── Dockerfile                 # python:3.11-slim, ENTRYPOINT python main.py
├── pyproject.toml             # Packaging metadata (setuptools, src layout)
├── requirements.txt           # Runtime deps: requests, rich
├── requirements-dev.txt       # build, twine, pytest, pytest-cov, ruff, black, mypy
└── docs/                      # This documentation + MVP spec
```

### v0.7.0 Data Flow

All presentation surfaces consume **one canonical report dictionary**:

```text
HTTP response → analyzer → findings[] ─┬─→ scorer → score{}
                                       │
                 build_json_report() ◄─┘  (scan metadata + summary)
                        │
        ┌───────────────┼────────────────┐
        ▼               ▼                ▼
   save_json()    render_markdown()  render_html()
   (--json)        (--markdown)       (--html)
        └───────────────┴────────────────┘
                        │
              CLI terminal / API / dashboard
```

---

## 3. Data Flow

### CLI scan

```text
argus-header https://example.com --verbose --json out.json
        │
        ▼
cli.main()
  ├─ argparse parses flags
  ├─ print_banner()
  ├─ scan_target(url, args)            [looped, or ThreadPool if --parallel]
  │    ├─ utils.normalize_url()         → "https://example.com"
  │    ├─ requester.fetch_headers()     → response_data dict  (or error dict)
  │    ├─ analyzer.analyze_headers()    → findings list
  │    ├─ reporter.print_report()       → Rich panel + severity-sorted table
  │    ├─ verbose.print_verbose(scan)   → (only if --verbose) 15 sections
  │    └─ build_json_report() → save_json()/save_markdown()/save_html()
  │                            (single-URL scans with --json/--markdown/--html)
  └─ exit codes: 0 ok · 130 Ctrl-C · 1 unexpected error
```

### API scan

```text
GET /analyze?url=https://example.com
        │
        ▼
fetch_headers(url) → success? ──no──► HTTP 400 {detail: error}
        │ yes
        ▼
analyze_headers(response_data) → findings[]
        │
        ▼
200 {url, status, headers, analysis, timing.backend_seconds}
```

---

## 4. Core Data Structures

### 4.1 `response_data` — produced by `requester.fetch_headers()`

Success:

```python
{
    "success": True,
    "url": "https://example.com/",        # final URL after redirects
    "status_code": 200,
    "headers": {"Content-Type": "text/html", ...},   # raw header dict
    "http_version": 11                    # urllib3 raw version code
}
```

Failure:

```python
{
    "success": False,
    "url": "<normalized target>",
    "error": "human-readable failure reason"
}
```

HTTP version codes are mapped in `verbose.py`: `9→HTTP/0.9`, `10→HTTP/1.0`, `11→HTTP/1.1`, `20→HTTP/2`, `30→HTTP/3`.

### 4.2 `findings[]` — produced by `analyzer.analyze_headers()`

Each finding is a dict with five keys:

```python
{
    "id":        str,     # stable rule ID, e.g. "SEC-001"
    "category":  "Security" | "Leakage" | "CORS" | "Performance" | "Cookie",
    "issue":     str,     # short title (may embed leaked value)
    "severity":  "HIGH" | "MEDIUM" | "LOW",
    "risk":      str,     # impact explanation
    "fix":       str      # actionable remediation
}
```

If the request failed (`success == False`), the analyzer returns `[]`.

### 4.3 `score{}` — produced by `scorer.calculate_score(findings)`

```python
{
    "score": int,            # 0-100, floor at 0: max(0, 100 - penalty)
    "grade": "A"|"B"|"C"|"D"|"F",
    "risk_level": "HIGH" | "MEDIUM" | "LOW",
    "total_findings": int,
    "penalty": int,
    "breakdown": {"HIGH": int, "MEDIUM": int, "LOW": int},
}
```

Grades: `≥90 A · ≥80 B · ≥70 C · ≥60 D · else F`. Risk level mirrors the highest finding severity present.

### 4.4 `scan` dict — assembled by `cli.scan_target()` for verbose mode

```python
{
    "scan_id":  uuid4().hex[:8],
    "started":  datetime,
    "finished": datetime,
    "duration": float,          # perf_counter delta of the analysis step
    "response": response_data,
    "findings": findings,
    "url":      original user-supplied url,
    "args":     argparse.Namespace
}
```

---

## 5. Module Reference

### 5.1 `src/argus_header/requester.py`

`fetch_headers(url, method="GET", follow_redirects=True, timeout=10) → dict`

- Normalizes the URL via `normalize_url`.
- Builds a `requests.Session` mounted with `HTTPAdapter(max_retries=Retry(total=3, backoff_factor=1, status_forcelist=[429,500,502,503,504]))` on both schemes.
- Sends the request with `User-Agent: HeaderScan-Tool/1.0`.
- Maps exceptions to friendly error strings: `Timeout`, `SSLError`, `ConnectionError`, `TooManyRedirects`, `MissingSchema`, `InvalidURL`, generic `RequestException`. **Never raises** — always returns a dict.

### 5.2 `src/argus_header/analyzer.py`

`analyze_headers(headers_data) → list[dict]`

Pure function; lowercases all header keys before evaluation. Every finding carries a stable rule ID. Rule groups executed in order:

1. **Security** — CSP (`SEC-001`), HSTS (`SEC-002`), X-Frame-Options (`SEC-003`, skipped when CSP present), X-Content-Type-Options (`SEC-004`)
2. **Leakage** — Server (`LEAK-001`, flags actual leaked value), X-Powered-By (`LEAK-002`)
3. **CORS** — wildcard `Access-Control-Allow-Origin: *` (`CORS-001`)
4. **Performance** — missing Cache-Control (`PERF-001`)
5. **Cookies** — delegates to `cookies.analyze_cookies()` (`COOKIE-001..003`)

See §6 for the full catalog.

### 5.3 `src/argus_header/cookies.py`

`analyze_cookies(headers) → list[dict]`

- Collects every `Set-Cookie` header (single or joined).
- Parses `name=value` plus attributes case-insensitively.
- Emits findings: missing **Secure** (`COOKIE-001`, MEDIUM), missing **HttpOnly** (`COOKIE-002`, MEDIUM), missing **SameSite** (`COOKIE-003`, LOW).
- A fully attributed cookie produces no findings.

### 5.4 `src/argus_header/scorer.py`

Scoring engine — three pure functions over the findings list:

| Function | Returns |
|---|---|
| `calculate_score(findings)` | `{score, grade, risk_level, total_findings, penalty, breakdown}` |
| `calculate_grade(score)` | `"A"…​"F"` (≥90 A · ≥80 B · ≥70 C · ≥60 D · else F) |
| `calculate_risk_level(findings)` | highest severity present, else `"LOW"` |

Penalty model (`PENALTIES` keyed by rule ID): CSP −20 · HSTS −20 · XFO −15 · XCTO −10 · X-Powered-By −8 · wildcard CORS −12 · Server −5 · Cache-Control −3 · cookie Secure −10 · HttpOnly −10 · SameSite −5. `score = max(0, 100 - penalty)`.

### 5.5 `src/argus_header/reporter.py`

- `print_report(response_data, findings, verbose=False)` — renders:
  - Error line when `success == False`
  - **Scan Summary** panel (target, status, header count)
  - **Analysis Findings** table sorted HIGH → MEDIUM → LOW with color-coded severities (red/yellow/blue) and a Rule column
  - Green *"No significant issues found!"* when clean; tip hint otherwise.
- `build_json_report(response_data, findings, score=None)` — assembles the canonical v0.7 report dict (§12): tool metadata, scan metadata (ID/target/final URL/ISO timestamp/duration/method/status), score block, summary counts, headers, findings.
- `save_json(report, filepath)` — writes the report dict with indent 4; friendly error on I/O failure.

### 5.6 `src/argus_header/markdown.py`

`render_markdown(report) → str` / `save_markdown(report, filepath)`

Renders the canonical report: title with target, score line (**NN / 100 — Grade X**), summary table, findings grouped by severity with Rule IDs and Risk/Fix, response headers table.

### 5.7 `src/argus_header/html_report.py`

`render_html(report) → str` / `save_html(report, filepath)`

Self-contained styled document (no external assets). All dynamic values pass through `html.escape()` before interpolation — untrusted header values cannot inject markup.

### 5.8 `src/argus_header/verbose.py`

`print_verbose(scan)` orchestrates 15 renderers, in order:

| # | Section | Content highlights |
|---|---|---|
| 1 | Scan Information | scan ID, start/finish timestamps, duration, Argus/Python versions, OS |
| 2 | Target Information | original vs final URL, hostname, port (defaults 80/443), protocol, method |
| 3 | Request Configuration | method, timeout, redirects, parallel, json path, verbose flag |
| 4 | Connection Information | decoded HTTP version, response time if recorded |
| 5 | HTTP Response | status, Content-Type/Length/Encoding, Server, Date |
| 6 | Redirect Information | compares original vs final URL |
| 7 | Response Headers | every header, pretty-printed |
| 8 | Security Headers | ✔/✘ against the 9-header watchlist |
| 9 | Missing Security Headers | red list |
| 10 | Present Security Headers | green list with values |
| 11 | Information Leakage | Server, X-Powered-By, Via, X-AspNet-Version, X-Runtime |
| 12 | Response Statistics | totals of received/present/missing headers |
| 13 | Findings Summary | HIGH/MEDIUM/LOW counts |
| 14 | Overall Assessment | overall risk = HIGH if any HIGH finding, else MEDIUM if any MEDIUM, else LOW |
| 15 | End of Scan | completion message, duration, version |

Watchlist constant `SECURITY_HEADERS`: Content-Security-Policy, Strict-Transport-Security, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, Cross-Origin-Opener-Policy, Cross-Origin-Embedder-Policy, Cross-Origin-Resource-Policy.

### 5.9 `src/argus_header/cli.py`

- Defines the ASCII banner and `--version`.
- `scan_target(url, args)` builds the `scan` dict, runs the analyzer, computes the score when enabled, assembles one canonical report via `build_json_report()`, then drives terminal output and every export (`--json`, `--markdown`, `--html`).
- `main()` argument parsing (§7), then:
  - `--parallel` + >1 URL → `ThreadPoolExecutor(max_workers=5)`
  - otherwise sequential with `console.rule()` separators
- Handles `KeyboardInterrupt` (exit 130) and top-level exceptions (exit 1).

### 5.10 `src/argus_header/schemas.py` (API layer)

Pydantic v2 models used only by `api.py`:

```python
class AnalyzeRequest(BaseModel): url: HttpUrl
class ScoreResult(BaseModel):    value:int; grade:str; risk_level:str; penalty:int
class Finding(BaseModel):        id:str; category:str; issue:str; severity:str; risk:str; fix:str
class AnalysisSummary(BaseModel): total_findings:int; high:int; medium:int; low:int
class AnalyzeResponse(BaseModel): url:str; status:int; headers:Dict[str,str];
                                  analysis:List[Finding]; score:Optional[ScoreResult];
                                  summary:AnalysisSummary; timing:Dict[str,float]
```

### 5.11 `src/argus_header/utils.py`

`normalize_url(url)` — prepends `https://` when no scheme is present; otherwise returns input unchanged.

### 5.12 `api.py` — FastAPI service

- CORS middleware: origins `*`, methods `*`, headers `*`, `allow_credentials=True`.
- `GET /analyze?url=...` and `POST /analyze` (body `{"url": "..."}` validated by `AnalyzeRequest`).
- On fetch failure → `HTTP 400` with the requester's error text.
- Success payload includes `score`, `summary`, and `timing.backend_seconds` (rounded to 4 decimals).
- Helper `get_backend_time(start, end)`.

### 5.13 `main.py` — legacy runner

Fetch → analyze → print → saves `report/<hostname>.json`. Superseded by the installed CLI; kept for Docker image default command.

---

## 6. Detection Rules Catalog

| Rule ID | Category | Trigger condition | Severity | Risk reported | Fix recommended |
|---|---|---|---|---|---|
| `SEC-001` | Security | No `Content-Security-Policy` | **HIGH** | XSS easier to exploit | Define allowed content sources via CSP |
| `SEC-002` | Security | No `Strict-Transport-Security` | **HIGH** | MITM protocol-downgrade attacks | `max-age=63072000; includeSubDomains` |
| `SEC-003` | Security | No `X-Frame-Options` **and** no CSP | **HIGH** | Clickjacking | `DENY` or `SAMEORIGIN` |
| `SEC-004` | Security | No `X-Content-Type-Options` | MEDIUM | MIME-sniffing → XSS | `nosniff` |
| `LEAK-001` | Leakage | `Server` present | LOW | Tech fingerprinting → CVE verification | Suppress/obfuscate header |
| `LEAK-002` | Leakage | `X-Powered-By` present | MEDIUM | Framework/version disclosure | Remove from server config |
| `CORS-001` | CORS | `Access-Control-Allow-Origin: *` | MEDIUM | Any origin can read resources (dangerous with auth) | Restrict to trusted domains |
| `PERF-001` | Performance | No `Cache-Control` | LOW | Inefficient browser caching | e.g. `max-age=3600` |
| `COOKIE-001` | Cookie | `Set-Cookie` without `Secure` | MEDIUM | Cookie sent over plaintext HTTP | Add the `Secure` attribute |
| `COOKIE-002` | Cookie | `Set-Cookie` without `HttpOnly` | MEDIUM | Readable by injected JavaScript (XSS) | Add the `HttpOnly` attribute |
| `COOKIE-003` | Cookie | `Set-Cookie` without `SameSite` | LOW | CSRF exposure | Add `SameSite=Lax` or `Strict` |

Score penalties per finding are listed in §5.4.

Notes:

- Header matching is case-insensitive.
- X-Frame-Options is considered satisfied if *any* CSP exists (frame-ancestors may cover it).
- Verbose mode *surfaces* additional headers (Referrer-Policy, Permissions-Policy, COOP/COEP/CORP, Via, X-AspNet-Version, X-Runtime) but these do **not yet generate findings** — see Roadmap/MVP gaps.

---

## 7. CLI Reference

```text
argus-header [-h] [-v] [--method {GET,HEAD}] [--no-redirect]
             [--timeout N] [--json FILE] [--score]
             [--markdown FILE] [--html FILE] [--parallel] [--verbose]
             url [url ...]
```

| Option | Default | Description |
|---|---|---|
| `url ...` | required (≥1) | One or more target URLs |
| `--method {GET,HEAD}` | `GET` | HTTP method used for probing |
| `--timeout N` | `10` | Per-request timeout in seconds |
| `--no-redirect` | off | Do not follow 3xx responses |
| `--parallel` | off | Scan multiple URLs concurrently (max 5 workers) |
| `--json FILE` | none | Write JSON report (v0.7 enhanced schema, single-target scans) |
| `--score` | off | Print Security Score / Grade / Risk / Penalty panel |
| `--markdown FILE` | none | Save a Markdown security report |
| `--html FILE` | none | Save an HTML security report (self-contained, escaped) |
| `--verbose` | off | Print full 15-section report after the summary table |
| `-v`, `--version` | — | Print `Argus Header <version>` and exit |
| `-h`, `--help` | — | Help with examples |

Exit codes: `0` success · `130` interrupted (Ctrl-C) · `1` unexpected error.

> ⚠️ URLs without a scheme get `https://` prepended automatically.

---

## 8. REST API Reference

Base URL (dev server): `http://127.0.0.1:8000`

Start with:

```bash
pip install fastapi uvicorn pydantic
uvicorn api:app --reload
```

Interactive docs: `/docs` (Swagger UI) · ReDoc at `/redoc`.

### `GET /analyze`

Fetch and analyze headers for `url`.

| Param | Type | In | Description |
|---|---|---|---|
| `url` | string | query | Target to scan |

**200 Response**

```json
{
  "url": "https://example.com/",
  "status": 200,
  "headers": {"content-type": "text/html; charset=UTF-8"},
  "analysis": [
    {
      "id": "SEC-001",
      "category": "Security",
      "issue": "Missing Content-Security-Policy",
      "severity": "HIGH",
      "risk": "XSS (Cross-Site Scripting) attacks are easier to exploit.",
      "fix": "Add a 'Content-Security-Policy' header defining allowed content sources."
    }
  ],
  "score": {"value": 27, "grade": "F", "risk_level": "HIGH", "penalty": 73},
  "summary": {"total_findings": 6, "high": 3, "medium": 2, "low": 1},
  "timing": {"backend_seconds": 0.4213}
}
```

**400 Response**

```json
{"detail": "Request timed out. The server took too long to respond."}
```

### `POST /analyze`

Same behavior; body validated by Pydantic:

```bash
curl -X POST http://127.0.0.1:8000/analyze \
     -H "Content-Type: application/json" \
     -d '{"url": "https://example.com"}'
```

Returns `{response, analysis, score, summary, timing}` where `response` is the full internal `response_data` dict.

### CORS

Open permissive policy (`allow_origins=["*"]`) so the static frontend can call it from anywhere during development. Tighten before production (see §16).

---

## 9. Web Dashboard (frontend)

Static, dependency-light SPA (Tailwind via CDN, Lucide icons, Inter font). No build step — open `index.html` directly or serve statically.

**Features**

- URL input with clear button, gradient glow, loading spinner state
- Calls `GET http://127.0.0.1:8000/analyze?url=<encoded>` *(hardcoded backend)*
- **Security Score panel**: numeric score, letter grade, risk level and penalty breakdown
- **Summary grid**: total findings + HIGH/MEDIUM/LOW counts
- Renders each finding as a color-coded card: border/icon/color per severity (HIGH=red alert-circle, MEDIUM=orange triangle, LOW=blue info), with Rule-ID chip, Risk and Fix fields
- Displays final URL, generated scan ID (client-side random), module count, backend timing
- Client-side errors surfaced in a red banner (including "backend not running" hint)
- All rendered values pass through an `escapeHtml()` helper
- **Export buttons**: download JSON / Markdown / HTML reports generated client-side from the API payload via Blob downloads

**Run it**

```bash
uvicorn api:app --reload          # terminal 1 — backend on :8000
python -m http.server 5500 --directory frontend   # terminal 2 — UI on :5500
```

---

## 10. Installation

### From PyPI

```bash
pip install argus-header
argus-header --version      # Argus Header 0.7.0
```

### From source

```bash
git clone https://github.com/heyshreee/argus-header.git
cd argus-header
python -m venv .venv && source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -e .
```

Runtime dependencies: `requests>=2.32.0`, `rich>=13.7.0`.
API extras (not yet declared in packaging): `fastapi`, `uvicorn`, `pydantic`.

---

## 11. Usage Examples

```bash
# Basic scan
argus-header https://example.com

# Scheme-less target (auto https)
argus-header example.com

# HEAD-only probe (faster, no body download)
argus-header https://example.com --method HEAD

# Full detailed report
argus-header https://example.com --verbose

# Fast timeout for fleet sweeps
argus-header https://site-a.com https://site-b.com --timeout 5

# Parallel multi-target scan
argus-header https://google.com https://github.com --parallel

# Disable redirect following (see the 301 itself)
argus-header http://example.com --no-redirect

# Export JSON
argus-header https://example.com --json report.json

# Show the security score & grade
argus-header https://example.com --score

# Export Markdown
argus-header https://example.com --markdown report.md

# Export HTML
argus-header https://example.com --html report.html

# Everything at once
argus-header https://example.com \
    --score \
    --json report.json \
    --markdown report.md \
    --html report.html
```

---

## 12. Report Formats (v0.7)

`--json`, `--markdown` and `--html` all render the **same canonical report dict** built by `reporter.build_json_report()`:

```json
{
    "schema_version": "0.7",
    "tool": {"name": "Argus Header", "version": "0.7.0"},
    "scan": {
        "id": "a1b2c3d4",
        "target": "https://example.com",
        "final_url": "https://example.com/",
        "timestamp": "2026-08-22T12:00:00.123456+00:00",
        "duration_seconds": 0.42,
        "method": "GET",
        "status": 200
    },
    "score": {"value": 27, "grade": "F", "risk_level": "HIGH", "penalty": 73},
    "summary": {"total_findings": 6, "high": 3, "medium": 2, "low": 1},
    "headers": {"...raw response headers...": ""},
    "findings": [
        {
            "id": "SEC-002",
            "category": "Security",
            "issue": "Missing Strict-Transport-Security",
            "severity": "HIGH",
            "risk": "Susceptible to Man-in-the-Middle (MITM) protocol downgrade attacks.",
            "fix": "Add 'Strict-Transport-Security: max-age=63072000; includeSubDomains'."
        }
    ]
}
```

Notes:

- The score is always computed and included in exports; `--score` only adds the terminal panel.
- `scan.timestamp` is a timezone-aware ISO-8601 string.
- Markdown renders: score line, summary table, findings grouped by severity with Rule IDs and Risk/Fix, response headers table.
- HTML is self-contained; every dynamic value is escaped with `html.escape()`.

---

## 13. Testing

Suites under `tests/` (pytest): `test_analyzer.py`, `test_scorer.py`, `test_cookies.py`, `test_requester.py`, `test_reporter.py`, `test_reporter_json.py`, `test_markdown.py`, `test_html_report.py`, `test_utils.py`.

Run:

```bash
pip install -r requirements-dev.txt
pytest tests/ -v                 # add --cov=src/argus_header for coverage
```

Current state: **37 tests, all passing**. Coverage highlights: `scorer`, `cookies`, `markdown`, `html_report`, `utils` at 100%; `analyzer` 96%. `cli.py`/`verbose.py` rendering paths are exercised only by manual smoke tests (roadmap item for 0.8.0).

Notes:

- Analyzer tests verify missing-CSP/HSTS detection, Server/X-Powered-By leaks, wildcard CORS, Cache-Control, and rule-ID presence.
- Scorer tests cover penalties, grade boundaries, risk levels and dynamic-leak prefix matching.
- Cookie tests cover Secure/HttpOnly/SameSite detection and fully-attributed cookies.
- Requester tests hit live network (example.com) plus a bogus host failure case — they are integration-style.

---

## 14. Docker Deployment

```bash
docker build -t argus-header .
docker run --rm argus-header https://example.com
```

Image: `python:3.11-slim`; deps installed from `requirements.txt`; project copied to `/app`; entrypoint `python main.py` (pass the URL as container args).

For the API in Docker, override the command:

```bash
docker run --rm -p 8000:8000 argus-header uvicorn api:app --host 0.0.0.0 --port 8000
```

---

## 15. Development Guide

```bash
git clone https://github.com/heyshreee/argus-header.git && cd argus-header
python -m venv .venv && source .venv/bin/activate
pip install -e .
pip install -r requirements-dev.txt
pytest tests/ -v
ruff check src/ tests/ && black src/ tests/ && mypy src/
```

Tooling available: `black` (format), `ruff` (lint), `mypy` (types), `pytest-cov` (coverage), `build`+`twine` (PyPI release).

Release flow (per CONTRIBUTING.md): fork → branch `feature/my-feature` → conventional commits (`feat: …`) → PR.

Packaging essentials (pyproject.toml):

- `[project.scripts] argus-header = "argus_header.cli:main"` — console command
- src-layout: `[tool.setuptools.packages.find] where=["src"]`
- Package data: bundled `*.json` inside `argus_header`

Build & publish:

```bash
python -m build
twine upload dist/*
```

---

## 16. Known Issues & Limitations

Track these before calling any release production-ready:

| # | Issue | Impact | Suggested fix |
|---|---|---|---|
| ~~K1~~ | ~~Broken `src.argus.*` imports~~ | — | **Fixed in v0.7.0** (all modules/tests import `argus_header.*`) |
| K2 | `fastapi`, `uvicorn`, `pydantic` missing from `requirements.txt`/extras | `uvicorn api:app` crashes without manual install | Add `[project.optional-dependencies] api = [...]` |
| K3 | Docker entrypoint runs `main.py` with no args → instant `exit 1` unless URL passed | Confusing first-run UX | Document arg passing or switch entrypoint to the CLI |
| K4 | CORS `allow_origins=["*"]` combined with `allow_credentials=True` | Invalid/insecure combo; browsers reject credentialed wildcard | List explicit origins, drop credentials or wildcard |
| K5 | Frontend hardcodes `http://127.0.0.1:8000` | Breaks when hosted elsewhere / over HTTPS (mixed content) | Derive base URL from `window.location` or config var |
| K6 | Verbose watchlist headers beyond cookies (Referrer-Policy, Permissions-Policy, COOP/COEP/CORP, Via, X-AspNet-Version, X-Runtime) not covered by analyzer rules | Findings ≠ verbose view; those headers never produce findings | Port remaining watchlist into the rule engine |
| ~~K7~~ | ~~`scan_time: "Now"` placeholder in JSON~~ | — | **Fixed in v0.7.0** (ISO-8601 UTC timestamps in canonical reports) |
| K8 | All export formats ignored for multi-URL scans; no per-URL files | Missing exports in batch mode | Write `<prefix>-<host>.<ext>` per target |
| K9 | No SSRF guard: API will fetch internal IPs / localhost | Abuse vector on public deployments | Validate public IPs, block private ranges |
| K10 | Requester/response time measured around analysis only, not network I/O; `response_time` key never set | Verbose shows "N/A" | Time inside `fetch_headers` |
| K11 | Tests perform real network calls | Slow/flaky CI | Mock with `responses`/`unittest.mock` |

---

## 17. Roadmap

| Version | Theme | Status |
|---|---|---|
| 0.6.0 | Verbose reporting | Released |
| 0.7.0 | Scoring & reports | Released |
| 0.8.0 | Quality | Next |
| 0.9.0 | Deep inspection | Planned |
| 1.0.0 | Stable | Planned |

- **0.6.0** (2026-08-02): 15-section `--verbose`, better output organization
- **0.7.0** (2026-08-22): Security Score 0–100, Grade A–F, cookie analysis, stable rule IDs, enhanced JSON, Markdown & HTML export, API/dashboard score integration
- **0.8.0** (next): expanded test coverage (CLI/verbose rendering), GitHub Actions CI, docs, architecture cleanup
- **0.9.0** (planned): TLS inspection, certificate analysis, HTTP/2 detection, advanced CORS analysis
- **1.0.0** (planned): production docs, comprehensive testing, complete analysis

---

## 18. Security & Legal Disclaimer

Argus Header is intended for **defensive security, auditing, learning, and authorized penetration testing only**. Only scan systems you own or have explicit permission to assess. The author is not responsible for misuse.

Released under the MIT License — see [`LICENSE`](../LICENSE).
