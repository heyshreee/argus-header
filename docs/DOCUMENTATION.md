# 🛡️ Argus Header — Complete Technical Documentation

> **Version:** 0.8.0 · **Language:** Python ≥ 3.9 · **License:** MIT
> **Author:** Sriram ( [@heyshreee](https://github.com/heyshreee) )

Argus Header is a fast, lightweight **HTTP security header analyzer**. It sends an HTTP request to one or more target URLs, inspects the response headers, and reports security misconfigurations, information leakage, CORS issues, and performance concerns — via a Rich CLI, a SARIF/JSON/HTML export, a REST API, and a web dashboard.

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

### Key Capabilities (v0.8.0)

- GET & HEAD requests, configurable timeout
- Automatic redirect following (optional) with retry/backoff on transient failures
- Single or multiple targets, optional parallel scanning (`ThreadPoolExecutor`, 5 workers)
- Deep security rules engine covering 9 rule families (CSP, CORS, Cookies, HSTS, Cache, Cross-Origin, Referrer, Permissions, Base Headers)
- Stable rule IDs on every finding (`ARGUS-CSP-*`, `ARGUS-HSTS-*`, `ARGUS-COOKIE-*`, …)
- Security Score Engine 2.0 (weighted, category-aware, 0–100, grade A+ down to F)
- YAML configuration (`.argus.yml`) via `--config`
- CI/CD gating via `--fail-on` and `--min-score`
- SARIF 2.1.0 report export (`--sarif`)
- Cyberpunk-style HTML report export (`--report`)
- `diff` command to compare two scan reports
- JSON / SARIF output to stdout
- Markdown report export (`--markdown`)
- Legacy HTML report export (`--html`)
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
│       ├── cli.py             # Argument parsing, banner, orchestration (v0.8)
│       ├── scanner.py         # v0.8 scan pipeline (rules + scoring + report)
│       ├── config_loader.py   # .argus.yml YAML configuration loader
│       ├── requester.py       # HTTP fetch engine (requests + retry)
│       ├── engine/            # Rules engine + scoring
│       │   ├── rules.py       # Rule registration & orchestration
│       │   ├── findings.py    # Structured finding model (Finding, as_dicts)
│       │   ├── policy.py      # CI/CD gate evaluation (--fail-on / --min-score)
│       │   ├── scoring.py     # Security Score Engine 2.0
│       │   └── references.py  # Reference documentation links
│       ├── analyzers/         # Per-header deep analyzers
│       │   ├── csp.py  cors.py  cookies.py  hsts.py  cache.py
│       │   ├── cross_origin.py  referrer.py  permissions.py
│       │   └── base_headers.py
│       ├── output/            # Report renderers
│       │   ├── json_report.py # JSON 0.8 renderer / loader
│       │   ├── sarif.py       # SARIF 2.1.0 renderer
│       │   ├── html_report.py # Cyberpunk-style HTML renderer
│       │   └── terminal.py    # Rich terminal output
│       ├── diff/              # Scan report comparison
│       │   └── scanner_diff.py
│       ├── models/            # Dataclasses (finding, report, configuration)
│       ├── verbose.py         # 15-section detailed report
│       ├── schemas.py         # Pydantic models for the API
│       └── utils.py           # URL normalization helper
├── api.py                     # FastAPI wrapper (GET/POST /analyze)
├── main.py                    # Legacy standalone runner (report/ dir output)
├── frontend/                  # Vanilla JS dashboard
├── tests/                     # pytest suites
├── Dockerfile                 # python:3.11-slim, ENTRYPOINT python main.py
├── pyproject.toml             # Packaging metadata (setuptools, src layout)
├── requirements.txt           # Runtime deps: requests, rich, pyyaml
├── requirements-dev.txt       # build, twine, pytest, pytest-cov, ruff, black, mypy
└── docs/                      # This documentation + MVP spec
```

### v0.8.0 Data Flow

All presentation surfaces consume **one canonical report dictionary** built by `output.json_report.build_report()`:

```text
HTTP response → fetch_headers → deep rules engine → findings[]
                                      │
                 calculate_score_2() ◄┘  (category-aware)
                         │
                  build_report()  (scan metadata + summary)
                         │
        ┌───────────────┼────────────────┐──────────────┐
        ▼               ▼                ▼              ▼
   save_report()   save_sarif()      save_html()   render_terminal()
   (--json)         (--sarif)        (--report)     (terminal / CI)
        └───────────────┴────────────────┘
              CLI terminal / API / dashboard
```

---

## 3. Data Flow

### CLI scan

```text
argus-header https://example.com --score --json out.json
        │
        ▼
cli.main()
  ├─ argparse parses flags
  ├─ load_config(args.config)           (optional .argus.yml)
  ├─ print_banner()
  ├─ scan_targets(args)
  │    └─ scan_target(url, method, follow_redirects, timeout, config)
  │         ├─ requester.fetch_headers() → response_data dict
  │         ├─ engine.rules.run_rules()  → findings list (9 rule families)
  │         ├─ engine.scoring.calculate_score_2() → ScoreData
  │         ├─ output.json_report.build_report()  → canonical v0.8 report
  │         └─ returns report dict
  ├─ _present_report()                    → Rich Scan Summary + findings table
  ├─ _handle_outputs()                    → --json/--sarif/--report/--html/--markdown
  └─ CI gate: evaluate_gate() + print_ci_result()  (--fail-on / --min-score)
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

### 4.3 `ScoreData` — produced by `engine.scoring.calculate_score_2()`

Security Score Engine 2.0 is **category-aware** and weighted across 5 categories that sum to 100:

```python
ScoreData(
    score=78,                 # 0-100, sum of surviving category scores
    grade="B",                # from A+ down to F
    risk_level="HIGH",        # worst severity present (CRITICAL/HIGH/MEDIUM/LOW)
    penalty=total_deduction,  # aggregate points deducted
    total_findings=int,
    categories={              # per-category surviving points
        "Content": 18, "Transport": 20, "Browser": 16,
        "Isolation": 10, "Cookies": 8,
    },
    max_per_category=25,
    breakdown={"CRITICAL": 0, "HIGH": 3, "MEDIUM": 2, "LOW": 1},
    weights={"Content": 25, "Transport": 20, "Browser": 25,
             "Isolation": 15, "Cookies": 15},
)
```

Category budgets: `Content 25 · Transport 20 · Browser 25 · Isolation 15 · Cookies 15`. Per-finding deductions: CRITICAL 9 · HIGH 7 · MEDIUM 4 · LOW 1. Each finding classifies into one category; scores floor at 0.

Grades: `≥98 A+ · ≥90 A · ≥80 B · ≥70 C · ≥60 D · else F`. Risk level mirrors the highest finding severity present.

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

### 5.2 `src/argus_header/engine/rules.py` (rules engine)

`run_rules(headers, config=None) → list[dict]`

- Normalizes header names to lowercase via `normalize_headers`.
- Executes every enabled rule family (see `RULES`), skipping any disabled by config.
- Aggregates findings from all analyzers into a flattened list of dicts.
- Each fallback-safe family is wrapped so a single analyzer failure degrades gracefully (logged, skipped).

Rule families registered in `RULES`:

| key | Analyzer | Focus |
|---|---|---|
| `csp` | `analyze_csp` | CSP directive analysis |
| `cors` | `analyze_cors` | CORS configuration |
| `cookies` | `analyze_cookies` | Cookie attribute security |
| `hsts` | `analyze_hsts` | HSTS configuration |
| `cache` | `analyze_cache` | Cache header policy |
| `cross_origin` | `analyze_cross_origin` | COOP / CORP / COEP |
| `referrer` | `analyze_referrer` | Referrer-Policy value |
| `permissions` | `analyze_permissions` | Permissions-Policy |
| `base_headers` | `analyze_base_headers` | XFO, XCTO, Server / X-Powered-By leaks |

### 5.3 `src/argus_header/analyzers/*.py` (deep analyzers)

Each module exposes a pure `analyze_*` function taking a lowercased header dict and returning a list of structured findings. Highlights:

- **csp.py — `analyze_csp`**: verifies `Content-Security-Policy` presence, parses directives, warns about missing/insecure directives (`unsafe-inline`, `unsafe-eval`, base-uri), flags weak `frame-ancestors`.
- **hsts.py — `analyze_hsts`**: checks presence, parses `max-age`, `includeSubDomains`, `preload`, flags missing or too-short max-age, missing includeSubDomains.
- **cors.py — `analyze_cors`**: flags wildcard `*` origins, unsafe reflections, missing `Access-Control-Allow-Origin`.
- **cookies.py — `analyze_cookies`**: per-cookie `Secure`/`HttpOnly`/`SameSite`/`domain` checks.
- **cache.py — `analyze_cache`**: missing `Cache-Control`, `no-store` variance, over-long max-age for sensitive content.
- **cross_origin.py — `analyze_cross_origin`**: COOP / CORP / COEP presence and values.
- **referrer.py — `analyze_referrer`**: `Referrer-Policy` presence and value safety.
- **permissions.py — `analyze_permissions`**: `Permissions-Policy` presence and defaults.
- **base_headers.py — `analyze_base_headers`**: X-Frame-Options, X-Content-Type-Options, Server / X-Powered-By leaks.

### 5.4 `src/argus_header/engine/scoring.py` (Score Engine 2.0)

| Function | Returns |
|---|---|
| `calculate_score_2(findings)` | `ScoreData` with aggregate score, category breakdown, grade, risk |
| `classify_finding(finding)` | scoring category (`Content`/`Transport`/`Browser`/`Isolation`/`Cookies`) |
| `calculate_grade_extended(score)` | grade from `"A+"` down to `"F"` (≥98 A+ · ≥90 A · ≥80 B · ≥70 C · ≥60 D · else F) |
| `calculate_risk_level_from_counts(counts)` | worst severity present, else `"LOW"` |
| `max_severity(findings)` | most severe finding level present |

Category budgets: `Content 25 · Transport 20 · Browser 25 · Isolation 15 · Cookies 15` (sum = 100). Severity deductions per finding: CRITICAL 9 · HIGH 7 · MEDIUM 4 · LOW 1. Category scores floor at 0; the overall score is the sum of surviving category scores.

### 5.5 `src/argus_header/engine/policy.py` (CI/CD gate)

`evaluate_gate(score, findings, fail_on="none", minimum_score=0) → GateResult`

- Fails when any finding exists at `fail_on` severity (or worse) using `SEVERITY_THRESHOLD`.
- Fails when the score is below `minimum_score` (default 80).
- Used by `--fail-on` and `--min-score` CLI flags.

### 5.6 `src/argus_header/output/` (report renderers)

| Module | Function | Output |
|---|---|---|
| `json_report.py` | `build_report(...)`, `render_json()`, `save_report()`, `load_report()` | Canonical v0.8 JSON report; load for `diff` |
| `sarif.py` | `build_sarif()`, `render_sarif()`, `save_sarif()` | SARIF 2.1.0 report |
| `html_report.py` | `render_html()`, `save_html()` | Cyberpunk-style self-contained HTML report |
| `terminal.py` | `print_findings_professional`, `print_score_breakdown`, `print_ci_result`, `print_diff_result` | Rich terminal output |

### 5.7 `src/argus_header/diff/scanner_diff.py`

`scan_diff(before_report, after_report) → DiffResult`

- Loads two JSON reports (`load_report` in `output.json_report`).
- Compares score, per-category scores, finding counts and severity changes.
- `print_diff_result()` (in `output.terminal`) renders the comparison.
- Invoked via `argus-header diff before.json after.json`.

### 5.8 `src/argus_header/config_loader.py`

`load_config(path) → Configuration | None`

- Loads a `.argus.yml` YAML configuration file.
- Maps to a typed `Configuration` object (method, timeout, redirects, rules gating, policy fail_on / minimum_score).
- Returns `None` when no path is given.

### 5.9 `src/argus_header/verbose.py`

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
| 13 | Findings Summary | CRITICAL/HIGH/MEDIUM/LOW counts |
| 14 | Overall Assessment | overall risk = worst severity present |
| 15 | End of Scan | completion message, duration, version |

### 5.10 `src/argus_header/cli.py`

- Defines the ASCII banner and `--version`.
- `scan_targets(args)` loads config, resolves method/timeout/redirects/fail_on/min_score, runs the v0.8 scan pipeline via `scan_target()`, presents reports, writes every requested export, and evaluates the CI gate.
- `run_diff(argv)` implements `argus-header diff <before.json> <after.json>`.
- `main()` argument parsing (§7):
  - `diff` subcommand → `run_diff`
  - `--parallel` + >1 URL → `ThreadPoolExecutor(max_workers=5)`
  - otherwise sequential
- Handles `KeyboardInterrupt` (exit 130) and top-level exceptions (exit 1).

### 5.11 `src/argus_header/scanner.py`

`scan_target(target, method, follow_redirects, timeout, config) → dict`

High-level v0.8 pipeline: fetch headers → run rules → score → build canonical report. On fetch failure returns an error report with `error` populated.

### 5.12 `src/argus_header/schemas.py` (API layer)

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

### 5.13 `src/argus_header/utils.py`

`normalize_url(url)` — prepends `https://` when no scheme is present; otherwise returns input unchanged.

### 5.14 `api.py` — FastAPI service

- CORS middleware: origins `*`, methods `*`, headers `*`, `allow_credentials=True`.
- `GET /analyze?url=...` and `POST /analyze` (body `{"url": "..."}` validated by `AnalyzeRequest`).
- On fetch failure → `HTTP 400` with the requester's error text.
- Success payload includes `score`, `summary`, and `timing.backend_seconds` (rounded to 4 decimals).
- Helper `get_backend_time(start, end)`.

### 5.13 `main.py` — legacy runner

Fetch → analyze → print → saves `report/<hostname>.json`. Superseded by the installed CLI; kept for Docker image default command.

---

## 6. Detection Rules Catalog

Findings in v0.8 carry stable `ARGUS-*` rule IDs grouped by rule family. The catalog below lists representative triggers; each analyzer may emit multiple rules per header.

| Rule ID | Family | Trigger condition (summary) | Severity | Risk reported | Fix recommended |
|---|---|---|---|---|---|
| `ARGUS-CSP-001` | CSP | No `Content-Security-Policy` | **CRITICAL** | XSS easier to exploit | Define allowed content sources via CSP |
| `ARGUS-CSP-002` | CSP | CSP too weak / no `default-src` | **HIGH** | Weak policy allows XSS | Tighten directives, add `default-src` |
| `ARGUS-CSP-003..006` | CSP | wildcard / unsafe-inline / unsafe-eval / http: in `default-src` | HIGH | Insecure source list | Restrict sources |
| `ARGUS-CSP-101..104` | CSP | weak `script-src` (wildcard/unsafe-inline/unsafe-eval/http:) | **HIGH** | Script injection risk | Restrict script sources |
| `ARGUS-CSP-201..204` | CSP | weak `frame-ancestors` | HIGH | Clickjacking | Restrict framing origins |
| `ARGUS-HSTS-001..004` | HSTS | missing HSTS / short max-age / missing includeSubDomains / no preload | HIGH | MITM protocol-downgrade | `max-age=63072000; includeSubDomains; preload` |
| `ARGUS-XFO-001` | Base | No `X-Frame-Options` | HIGH | Clickjacking | `DENY` or `SAMEORIGIN` |
| `ARGUS-XCTO-001` | Base | No `X-Content-Type-Options` | MEDIUM | MIME-sniffing → XSS | `nosniff` |
| `ARGUS-XCTO-002` | Base | XCTO not `nosniff` | LOW | MIME-sniffing allowed | `nosniff` |
| `ARGUS-SERVER-001` | Base | `Server` header present | LOW | Tech fingerprinting → CVE verification | Suppress/obfuscate header |
| `ARGUS-SERVER-002` | Base | `X-Powered-By` present | MEDIUM | Framework/version disclosure | Remove from server config |
| `ARGUS-CORS-001` | CORS | Wildcard `*` origin | MEDIUM | Any origin reads resources | Restrict to trusted domains |
| `ARGUS-CORS-002..006` | CORS | unsafe reflection / missing headers / origins order | MEDIUM | Credentialed cross-origin reads | Tighten allowlist |
| `ARGUS-COOKIE-001` | Cookie | Set-Cookie without `Secure` | MEDIUM | Cookie over plaintext HTTP | Add `Secure` |
| `ARGUS-COOKIE-002` | Cookie | Set-Cookie without `HttpOnly` | MEDIUM | Readable by injected JS (XSS) | Add `HttpOnly` |
| `ARGUS-COOKIE-003` | Cookie | Set-Cookie without `SameSite` | LOW | CSRF exposure | `SameSite=Lax`/`Strict` |
| `ARGUS-COOKIE-004..008` | Cookie | domain/path/max-age/prefix issues | LOW | Mis-scoped cookies | Tighten cookie scope |
| `ARGUS-CACHE-001` | Cache | No `Cache-Control` | LOW | Inefficient caching | e.g. `max-age=3600` |
| `ARGUS-CACHE-002` | Cache | `no-cache`/`no-store` on stable content | LOW | Re-fetch inefficiency | Tune `max-age`/`immutable` |
| `ARGUS-CACHE-003` | Cache | over-long max-age on sensitive content | LOW | Stale sensitive cache | Shorten or `no-store` |
| `ARGUS-COOP-001/002` | Cross-Origin | missing / permissive COOP | MEDIUM | cross-origin isolation gaps | `same-origin` |
| `ARGUS-COEP-001/002` | Cross-Origin | missing / permissive COEP | MEDIUM | cross-origin isolation gaps | `require-corp` + CORP |
| `ARGUS-CORP-001` | Cross-Origin | missing CORP | LOW | cross-origin reads | Restrict CORP |
| `ARGUS-REFERRER-001..003` | Referrer | missing Referrer-Policy / weak value (`no-referrer-when-downgrade`) | LOW/MEDIUM | Referrer leakage | `strict-origin-when-cross-origin` |
| `ARGUS-PERMISSIONS-001..003` | Permissions | missing Permissions-Policy / permissive defaults | LOW/MEDIUM | Feature abuse | `permissions-policy` allowlist |

Score penalties per finding are listed in §5.4 (Score Engine 2.0 category deductions).

Notes:

- Header matching is case-insensitive (normalized to lowercase before analysis).
- X-Frame-Options is considered satisfied if *any* CSP `frame-ancestors` exists.
- The legacy `SEC-*`/`LEAK-*`/`CORS-*`/`PERF-*`/`COOKIE-*` IDs from v0.7 are no longer emitted by the deep engine; the Score 2.0 classifier can still *reverse-map* legacy category strings for backward compatibility.

---

## 7. CLI Reference

```text
argus-header [-h] [-v] [--method {GET,HEAD}] [--no-redirect]
             [--timeout N] [--config FILE] [--score]
             [--json [FILE]] [--sarif [FILE]] [--report FILE]
             [--markdown FILE] [--html FILE] [--parallel] [--verbose]
             [--fail-on {critical,high,medium,low,none}]
             [--min-score N]
             url [url ...]

argus-header diff <before.json> <after.json>
```

| Option | Default | Description |
|---|---|---|
| `url ...` | required (≥1) | One or more target URLs |
| `--method {GET,HEAD}` | `GET` | HTTP method used for probing |
| `--timeout N` | `10` | Per-request timeout in seconds |
| `--no-redirect` | off | Do not follow 3xx responses |
| `--config FILE` | none | Load a `.argus.yml` configuration file |
| `--json [FILE]` | none | Write JSON report (v0.8 schema); stdout when FILE omitted |
| `--sarif [FILE]` | none | Write a SARIF 2.1.0 report; stdout when FILE omitted |
| `--report FILE` | none | Save a cyberpunk-style HTML security report |
| `--score` | off | Print the full Security Score 2.0 breakdown (score, grade, categories, risk) |
| `--fail-on {critical,high,medium,low,none}` | `none` | CI mode: fail build on findings at/above this severity |
| `--min-score N` | `80` | CI mode: fail build when score is below N |
| `--markdown FILE` | none | Save a Markdown security report |
| `--html FILE` | none | Save a legacy HTML security report (self-contained, escaped) |
| `--parallel` | off | Scan multiple URLs concurrently (max 5 workers) |
| `--verbose` | off | Print full 15-section report after the summary table |
| `diff` | — | Compare two scan reports (`argus-header diff before.json after.json`) |
| `-v`, `--version` | — | Print `Argus Header <version>` and exit |
| `-h`, `--help` | — | Help with examples |

Exit codes: `0` success · `130` interrupted (Ctrl-C) · `1` unexpected error (or CI gate failure).

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
argus-header --version      # Argus Header 0.8.0
```

### From source

```bash
git clone https://github.com/heyshreee/argus-header.git
cd argus-header
python -m venv .venv && source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -e .
```

Runtime dependencies: `requests>=2.32.0`, `rich>=13.7.0`, `pyyaml>=6.0.0`.
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

# Export JSON (file, or stdout when FILE omitted)
argus-header https://example.com --json report.json
argus-header https://example.com --json

# Export SARIF 2.1.0
argus-header https://example.com --sarif report.sarif
argus-header https://example.com --sarif

# Export cyberpunk-style HTML report
argus-header https://example.com --report report.html

# Show the security score 2.0 breakdown & grade
argus-header https://example.com --score

# CI gating — fail the build on high-severity findings
argus-header https://example.com --fail-on high

# CI gating — fail the build when score < 80
argus-header https://example.com --min-score 80

# Load a YAML configuration
argus-header https://example.com --config .argus.yml

# Compare two scan reports
argus-header diff before.json after.json

# Export Markdown
argus-header https://example.com --markdown report.md

# Export HTML
argus-header https://example.com --html report.html

# Everything at once
argus-header https://example.com \
    --score \
    --json report.json \
    --sarif report.sarif \
    --markdown report.md \
    --html report.html
```

---

## 12. Report Formats (v0.8)

`--json`, `--markdown`, `--html`, `--report` and `--sarif` all operate on the **same canonical v0.8 report dict** built by `output.json_report.build_report()`:

```json
{
    "schema_version": "0.8",
    "tool": {"name": "Argus Header", "version": "0.8.0"},
    "scan": {
        "id": "a1b2c3d4",
        "target": "https://example.com",
        "final_url": "https://example.com/",
        "timestamp": "2026-09-03T12:00:00.123456+00:00",
        "duration_seconds": 0.42,
        "method": "GET",
        "status": 200
    },
    "score": {
        "value": 27, "grade": "F", "risk_level": "HIGH", "penalty": 73,
        "total_findings": 6,
        "categories": {"Content": 4, "Transport": 4, "Browser": 4, "Isolation": 14, "Cookies": 11},
        "max_per_category": 25,
        "breakdown": {"CRITICAL": 0, "HIGH": 3, "MEDIUM": 2, "LOW": 1},
        "weights": {"Content": 25, "Transport": 20, "Browser": 25, "Isolation": 15, "Cookies": 15}
    },
    "summary": {"total_findings": 6, "critical": 0, "high": 3, "medium": 2, "low": 1},
    "headers": {"...raw response headers...": ""},
    "findings": [
        {
            "id": "ARGUS-CSP-001",
            "category": "Security",
            "title": "Missing Content-Security-Policy",
            "severity": "CRITICAL",
            "risk": "XSS (Cross-Site Scripting) attacks are easier to exploit.",
            "fix": "Add a 'Content-Security-Policy' header defining allowed content sources."
        }
    ],
    "config": {
        "policy": {"minimum_score": 80, "fail_on": "none"},
        "rules": {"csp": true, "cors": true, "cookies": true, "hsts": true,
                  "cache": true, "cross_origin": true, "referrer": true,
                  "permissions": true, "base_headers": true}
    }
}
```

Notes:

- The score is always computed and included in exports; `--score` only adds the terminal panel.
- `scan.timestamp` is a timezone-aware ISO-8601 string.
- `--sarif` renders a SARIF 2.1.0 document (rules, results, severity levels) from the same findings.
- `--json` and `--sarif` accept an optional `FILE`; when omitted they print to stdout.
- Markdown renders: score line, summary table, findings grouped by severity with Rule IDs and Risk/Fix, response headers table.
- HTML (legacy `--html`) is self-contained and escapes every dynamic value with `html.escape()`.

---

## 13. Testing

Suites under `tests/` (pytest):

- **Legacy engine**: `test_analyzer.py`, `test_scorer.py`, `test_cookies.py`, `test_reporter.py`, `test_reporter_json.py`, `test_markdown.py`, `test_html_report.py`
- **v0.8 engine**: `test_analyzers.py` (deep analyzers), `test_rules.py`, `test_policy.py`, `test_scoring.py`, `test_sarif.py`, `test_diff.py`
- **Transport/util**: `test_requester.py`, `test_utils.py`, `test_json.py`, `test_csp.py`, `test_hsts.py`, `test_cors.py`, `test_cookie_security.py`

Run:

```bash
pip install -r requirements-dev.txt
pytest tests/ -v                 # add --cov=src/argus_header for coverage
```

Notes:

- Analyzer/rule tests verify per-header detection across the 9 rule families and `ARGUS-*` rule-ID presence.
- Scoring tests cover Score Engine 2.0 category budgets, grade boundaries (A+..F), risk levels, and severity deductions.
- Policy tests cover CI gating (`--fail-on`, `--min-score`).
- SARIF tests verify valid SARIF 2.1.0 output shape.
- Diff tests verify report comparison behavior.
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
| ~~K6~~ | ~~Verbose watchlist headers not covered by analyzer rules~~ | — | **Fixed in v0.8.0** (deep engine now covers Referrer-Policy, Permissions-Policy, COOP/COEP/CORP) |
| ~~K7~~ | ~~`scan_time: "Now"` placeholder in JSON~~ | — | **Fixed in v0.7.0** (ISO-8601 UTC timestamps in canonical reports) |
| K2 | `fastapi`, `uvicorn`, `pydantic` missing from `requirements.txt`/extras | `uvicorn api:app` crashes without manual install | Add `[project.optional-dependencies] api = [...]` |
| K3 | Docker entrypoint runs `main.py` with no args → instant `exit 1` unless URL passed | Confusing first-run UX | Document arg passing or switch entrypoint to the CLI |
| K4 | CORS `allow_origins=["*"]` combined with `allow_credentials=True` | Invalid/insecure combo; browsers reject credentialed wildcard | List explicit origins, drop credentials or wildcard |
| K5 | Frontend hardcodes `http://127.0.0.1:8000` | Breaks when hosted elsewhere / over HTTPS (mixed content) | Derive base URL from `window.location` or config var |
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
| 0.8.0 | Deep analysis engine | Released |
| 0.9.0 | Deep inspection | Next |
| 1.0.0 | Stable | Planned |

- **0.6.0** (2026-08-02): 15-section `--verbose`, better output organization
- **0.7.0** (2026-08-22): Security Score 0–100, Grade A–F, cookie analysis, stable rule IDs, enhanced JSON, Markdown & HTML export, API/dashboard score integration
- **0.8.0** (2026-09-03): Deep rules engine (9 rule families), Score Engine 2.0 (A+ grades), SARIF + cyberpunk HTML exports, `diff` command, CI/CD gating, YAML config
- **0.9.0** (next): TLS inspection, certificate analysis, HTTP/2 detection, advanced CORS analysis
- **1.0.0** (planned): production docs, comprehensive testing, complete analysis

---

## 18. Security & Legal Disclaimer

Argus Header is intended for **defensive security, auditing, learning, and authorized penetration testing only**. Only scan systems you own or have explicit permission to assess. The author is not responsible for misuse.

Released under the MIT License — see [`LICENSE`](../LICENSE).
