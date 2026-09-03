# 🛡️ Argus Header

> Fast, lightweight HTTP security header analyzer built for developers, security engineers, and penetration testers.

![Python](https://img.shields.io/badge/Python-3.9+-blue.svg)
![Version](https://img.shields.io/badge/version-v0.8.0-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)

Argus Header is a command-line tool that analyzes HTTP response headers and identifies common security misconfigurations, information leakage, and HTTP security best-practice issues. It scores each target from 0–100 with a letter grade and exports reports as JSON, Markdown, or HTML.

---

# ✨ Features

## HTTP Request Engine

- ✅ GET & HEAD request support
- ✅ Configurable request timeout
- ✅ Redirect handling
- ✅ Retry mechanism
- ✅ Multiple URL scanning
- ✅ Parallel scanning

## Security Analysis

Detects missing security headers including:

- Content-Security-Policy (CSP)
- Strict-Transport-Security (HSTS)
- X-Frame-Options
- X-Content-Type-Options

## Security Score & Grade

- Security Score from 0–100
- Letter Grade from A–F
- Risk level and penalty breakdown
- Stable rule IDs for every finding (e.g. `SEC-001`, `COOKIE-002`)

## Cookie Analysis

Analyzes `Set-Cookie` attributes:

- Secure flag (MEDIUM)
- HttpOnly flag (MEDIUM)
- SameSite attribute (LOW)

## Information Leakage Detection

Detects exposed:

- Server
- X-Powered-By

## CORS Analysis

Detects:

- Wildcard `Access-Control-Allow-Origin: *`

## Performance Checks

Analyzes:

- Cache-Control

## Reports

- Rich CLI output
- Detailed `--verbose` mode
- JSON report export (enhanced v0.8 schema)
- SARIF 2.1.0 report export
- Markdown report export
- HTML report export (self-contained, escaped)
- Cyberpunk-style HTML report export (`--report`)
- Severity levels
- Security recommendations
- CI/CD gating (`--fail-on`, `--min-score`)
- YAML configuration support (`--config`)

---

# 🔍 Verbose Mode

The `--verbose` option provides a comprehensive scan report including:

- Scan Information
- Target Information
- Request Configuration
- Connection Information
- HTTP Response Details
- Redirect Information
- Response Headers
- Security Headers
- Missing Security Headers
- Present Security Headers
- Information Leakage
- Response Statistics
- Findings Summary
- Overall Assessment
- End of Scan Summary

---

# 📦 Installation

## Install from PyPI

```bash
pip install argus-header
```

Verify installation:

```bash
argus-header --version
```

Expected output:

```text
Argus Header 0.8.0
```

---

## Install from Source

```bash
git clone https://github.com/heyshreee/argus-header.git

cd argus-header

python -m venv .venv
```

### Windows

```powershell
.venv\Scripts\activate
```

### Linux / macOS

```bash
source .venv/bin/activate
```

Install:

```bash
pip install -e .
```

---

# 🚀 Usage

Basic Scan

```bash
argus-header https://example.com
```

HEAD Request

```bash
argus-header https://example.com --method HEAD
```

Verbose Report

```bash
argus-header https://example.com --verbose
```

Custom Timeout

```bash
argus-header https://example.com --timeout 5
```

Multiple URLs

```bash
argus-header https://google.com https://github.com --parallel
```

Disable Redirects

```bash
argus-header https://example.com --no-redirect
```

Export JSON

```bash
argus-header https://example.com --json report.json
```

Security Score & Grade

```bash
argus-header https://example.com --score
```

Export Markdown Report

```bash
argus-header https://example.com --markdown report.md
```

Export HTML Report

```bash
argus-header https://example.com --html report.html
```

All Export Formats Together

```bash
argus-header https://example.com \
    --score \
    --json report.json \
    --markdown report.md \
    --html report.html
```

Export SARIF Report

```bash
argus-header https://example.com --sarif report.sarif
argus-header https://example.com --sarif          # stdout
```

Export Cyberpunk-style HTML Report

```bash
argus-header https://example.com --report report.html
```

CI/CD Gating

```bash
argus-header https://example.com --fail-on high
argus-header https://example.com --min-score 80
```

YAML Configuration

```bash
argus-header https://example.com --config .argus.yml
```

Compare Two Reports

```bash
argus-header diff before.json after.json
```

Display Version

```bash
argus-header --version
```

Display Help

```bash
argus-header --help
```

---

# ⚙️ Command Line Options

| Option | Description |
|---------|-------------|
| `--method` | HTTP Method (GET / HEAD) |
| `--timeout` | Request timeout |
| `--parallel` | Scan multiple URLs concurrently |
| `--config FILE` | Load a .argus.yml configuration file |
| `--json [FILE]` | Save report as JSON (v0.8 schema); stdout when FILE omitted |
| `--sarif [FILE]` | Save a SARIF 2.1.0 report; stdout when FILE omitted |
| `--report FILE` | Save a cyberpunk-style HTML security report |
| `--score` | Display the Security Score 2.0 breakdown and grade |
| `--fail-on` | CI mode: fail the build on findings at/above severity (critical/high/medium/low/none) |
| `--min-score N` | CI mode: fail the build when the score is below N |
| `--markdown FILE` | Save a Markdown security report |
| `--html FILE` | Save a legacy HTML security report |
| `--no-redirect` | Disable redirect following |
| `diff` | Compare two JSON reports (`argus-header diff before.json after.json`) |
| `--verbose` | Display detailed scan report |
| `--version` | Display tool version |
| `--help` | Show help information |

---

# 📋 Example Output

```code
$ argus-header https://example.com --score

   ___                             
  / _ | _______ _____ _____ _____  
 / __ |/ __/ _ `/ // (_-</(_-<(_-<  
/_/ |_/_/  \_, /\_,_/___/___/___/  
            /_/                    

 ARGUS-HEADER v0.8.0
 DEEP SECURITY ANALYSIS

 Argus Header
 HTTP Header Security Analyzer

Version: 0.8.0

╭──────── Scan Summary ────────╮
│ Target: https://example.com/ │
│ Status: 200                  │
│ Headers Found: 11            │
╰──────────────────────────────╯
                                     Analysis Findings                                     
┏━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ Severity     ┃ Issue                     ┃ Risk                      ┃ Recommendation            ┃
┡━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━┩
│ HIGH         │ Missing                   │ XSS (Cross-Site           │ Add a                     │
│              │ Content-Security-Policy   │ Scripting) attacks are    │ 'Content-Security-Policy' │
│              │                           │ easier to exploit.        │ header defining allowed   │
│              │                           │                           │ content sources.          │
│ HIGH         │ Missing                   │ Susceptible to            │ Add                       │
│              │ Strict-Transport-Security │ Man-in-the-Middle (MITM)  │ 'Strict-Transport-Securi… │
│              │                           │ protocol downgrade        │ max-age=63072000;         │
│              │                           │ attacks.                  │ includeSubDomains'.       │
│ HIGH         │ Missing X-Frame-Options   │ Vulnerable to             │ Add 'X-Frame-Options:     │
│              │                           │ Clickjacking attacks.     │ DENY' or 'SAMEORIGIN'.    │
│ MEDIUM       │ Missing                   │ Browsers may MIME-sniff   │ Add                       │
│              │ X-Content-Type-Options    │ the response body,        │ 'X-Content-Type-Options:  │
│              │                           │ leading to XSS.           │ nosniff'.                 │
│ LOW          │ Server Header Leaked:     │ Reveals server            │ Configure server to       │
│              │ cloudflare                │ technology, helping       │ suppress or obfuscate the │
│              │                           │ attackers verify CVEs.    │ 'Server' header.          │
│ LOW          │ Missing Cache-Control     │ Browser may not cache     │ Add 'Cache-Control'       │
│              │ Header                    │ resources efficiently,    │ header (e.g.,             │
│              │                           │ slowing load times.       │ max-age=3600).            │
└──────────────┴───────────────────────────┴───────────────────────────┴───────────────────────────┘

Tip: Run with --verbose to view detailed scan information.
╭─ Security Score 2.0 ─────────────╮
│ Overall: 27/100          Grade F │
│ Content:    4/25                 │
│ Transport:  0/20                 │
│ Browser:    4/25                 │
│ Isolation:  10/15                │
│ Cookies:    8/15                 │
│ Risk: HIGH                       │
╰──────────────────────────────────╯
```

---

# 🔐 Security Analysis

The v0.8 engine runs **9 rule families** over the response headers:

- Content-Security-Policy (CSP)
- Cross-Origin Resource Sharing (CORS)
- Cookies (Secure, HttpOnly, SameSite, domain/path)
- HTTP Strict Transport Security (HSTS)
- Cache-Control
- Cross-Origin Policies (COOP / COEP / CORP)
- Referrer-Policy
- Permissions-Policy
- Base Security Headers (X-Frame-Options, X-Content-Type-Options, Server/X-Powered-By leaks)

---

# 📁 Project Structure

```text
argus-header/

src/
└── argus_header/
    ├── __init__.py
    ├── __main__.py
    ├── cli.py                # argument parsing & orchestration (v0.8)
    ├── scanner.py            # v0.8 scan pipeline
    ├── config_loader.py      # YAML config (.argus.yml)
    ├── requester.py          # HTTP fetch engine (retries, redirects)
    ├── analyzer.py           # legacy rule engine
    ├── cookies.py            # legacy Set-Cookie analysis
    ├── scorer.py             # legacy score / grade engine
    ├── reporter.py           # legacy terminal output
    ├── markdown.py           # Markdown report renderer
    ├── html_report.py        # legacy HTML report renderer
    ├── verbose.py            # 15-section detailed report
    ├── schemas.py            # Pydantic models for the API layer
    ├── utils.py              # URL normalization
    ├── engine/               # rules engine + scoring
    │   ├── rules.py          # rule registration & orchestration
    │   ├── findings.py       # structured finding model
    │   ├── policy.py         # CI/CD gate evaluation
    │   ├── scoring.py        # Security Score 2.0
    │   └── references.py     # reference documentation links
    ├── analyzers/            # per-header deep analyzers
    │   ├── csp.py  cors.py  cookies.py  hsts.py  cache.py
    │   ├── cross_origin.py  referrer.py  permissions.py
    │   └── base_headers.py
    ├── output/               # report renderers
    │   ├── json_report.py    # JSON 0.8 renderer
    │   ├── sarif.py          # SARIF 2.1.0 renderer
    │   ├── html_report.py    # cyberpunk HTML renderer
    │   └── terminal.py       # Rich terminal output
    ├── diff/                 # scan report comparison
    │   └── scanner_diff.py
    └── models/               # dataclasses (finding, report, config)

api.py                     # FastAPI service (GET/POST /analyze)
frontend/                  # vanilla JS dashboard with score panel & exports
tests/
docs/

README.md
CHANGELOG.md
CONTRIBUTING.md
LICENSE
pyproject.toml
```

---

# 🗺️ Roadmap

## ✅ v0.8.0 — Current Release

### Added

- Deep security rules engine (9 rule families)
- Security Score Engine 2.0 with A+ grades
- YAML configuration support (`--config .argus.yml`)
- SARIF 2.1.0 report export (`--sarif`)
- Cyberpunk-style HTML report export (`--report`)
- `diff` command for comparing two scan reports
- CI/CD gating via `--fail-on` and `--min-score`
- JSON / SARIF stdout output
- Expanded test coverage

### Changed

- Rewrote CLI for the v0.8 scan pipeline
- Rewrote output renderers and analyzer layer
- New `engine/`, `analyzers/`, `output/`, `diff/`, `models/` package structure
- Added CRITICAL severity level

---

## 🚀 v0.9.0 — Next

Planned features:

- TLS Inspection
- Certificate Analysis
- HTTP/2 Detection
- Advanced CORS Analysis

---

## 🎉 v1.0.0

- Stable Public Release
- Production-ready Documentation
- Comprehensive Testing
- Complete HTTP Security Analysis

---

# 💻 Development

Clone the repository:

```bash
git clone https://github.com/heyshreee/argus-header.git

cd argus-header
```

Install the development version:

```bash
python -m venv .venv

# Windows
.venv\Scripts\activate

# Linux / macOS
source .venv/bin/activate

pip install -e .
pip install -r requirements-dev.txt
```

Run:

```bash
argus-header https://example.com
```

Run verbose mode:

```bash
argus-header https://example.com --verbose
```

Run the test suite and static checks:

```bash
pytest tests/ -v
ruff check src/ tests/
black --check src/ tests/
mypy src/
```

---

# 🤝 Contributing

Contributions are welcome.

1. Fork the repository.

2. Create a feature branch.

```bash
git checkout -b feature/my-feature
```

3. Commit your changes.

```bash
git commit -m "feat: add awesome feature"
```

4. Push your branch.

```bash
git push origin feature/my-feature
```

5. Open a Pull Request.

Please read **CONTRIBUTING.md** before submitting major changes.

---

# 📄 License

Released under the MIT License.

See the `LICENSE` file for details.

---

# 👨‍💻 Author

**Sriram**

GitHub: https://github.com/heyshreee

PyPI: https://pypi.org/project/argus-header/

---

# ⚠️ Disclaimer

Argus Header is intended for defensive security, security auditing, learning, and authorized penetration testing only.

Only scan systems that you own or have explicit permission to assess.

The author is not responsible for misuse of this software.