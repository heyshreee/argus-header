# 🛡️ Argus Header

> Fast, lightweight HTTP security header analyzer built for developers, security engineers, and penetration testers.

![Python](https://img.shields.io/badge/Python-3.9+-blue.svg)
![Version](https://img.shields.io/badge/version-v0.7.0-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)

Argus Header is a command-line tool that analyzes HTTP response headers and identifies common security misconfigurations, information leakage, and HTTP security best-practice issues. It provides both a concise summary and a detailed verbose report for security assessments.

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
- JSON report export (enhanced v0.7 schema)
- Markdown report export
- HTML report export (self-contained, escaped)
- Severity levels
- Security recommendations

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
Argus Header 0.7.0
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
| `--json FILE` | Save report as JSON (v0.7 enhanced schema) |
| `--score` | Display the security score and grade |
| `--markdown FILE` | Save a Markdown security report |
| `--html FILE` | Save an HTML security report |
| `--no-redirect` | Disable redirect following |
| `--verbose` | Display detailed scan report |
| `--version` | Display tool version |
| `--help` | Show help information |

---

# 📋 Example Output

```code
(.venv) PS C:\pr0j3t\argus-header> argus-header https://example.com --verbose         

   ___                             
  / _ | _______ _____ _____ _____  
 / __ |/ __/ _ `/ // (_-</(_-<(_-<  
/_/ |_/_/  \_, /\_,_/___/___/___/  
            /_/                    

 Argus Header
 HTTP Header Security Analyzer

Version: 0.7.0

╭──────── Scan Summary ────────╮
│ Target: https://example.com/ │
│ Status: 200                  │
│ Headers Found: 11            │
╰──────────────────────────────╯
                                                    Analysis Findings                                                     
┏━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ Severity     ┃ Issue                            ┃ Risk                              ┃ Recommendation                   ┃
┡━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┩
│ HIGH         │ Missing Content-Security-Policy  │ XSS (Cross-Site Scripting)        │ Add a 'Content-Security-Policy'  │
│              │                                  │ attacks are easier to exploit.    │ header defining allowed content  │
│              │                                  │                                   │ sources.                         │
│ HIGH         │ Missing                          │ Susceptible to Man-in-the-Middle  │ Add 'Strict-Transport-Security:  │
│              │ Strict-Transport-Security        │ (MITM) protocol downgrade         │ max-age=63072000;                │
│              │                                  │ attacks.                          │ includeSubDomains'.              │
│ HIGH         │ Missing X-Frame-Options          │ Vulnerable to Clickjacking        │ Add 'X-Frame-Options: DENY' or   │
│              │                                  │ attacks.                          │ 'SAMEORIGIN'.                    │
│ MEDIUM       │ Missing X-Content-Type-Options   │ Browsers may MIME-sniff the       │ Add 'X-Content-Type-Options:     │
│              │                                  │ response body, leading to XSS.    │ nosniff'.                        │
│ LOW          │ Server Header Leaked: cloudflare │ Reveals server technology,        │ Configure server to suppress or  │
│              │                                  │ helping attackers verify CVEs.    │ obfuscate the 'Server' header.   │
│ LOW          │ Missing Cache-Control Header     │ Browser may not cache resources   │ Add 'Cache-Control' header       │
│              │                                  │ efficiently, slowing load times.  │ (e.g., max-age=3600).            │
└──────────────┴──────────────────────────────────┴───────────────────────────────────┴──────────────────────────────────┘

```

---

# 🔐 Security Analysis

## Security Headers

Checks for:

- Content-Security-Policy
- Strict-Transport-Security
- X-Frame-Options
- X-Content-Type-Options

## Information Leakage

Checks for:

- Server
- X-Powered-By

## CORS

Checks for:

- Wildcard Access-Control-Allow-Origin

## Performance

Checks for:

- Cache-Control

---

# 📁 Project Structure

```text
argus-header/

src/
└── argus_header/
    ├── __init__.py
    ├── __main__.py
    ├── analyzer.py
    ├── cli.py
    ├── reporter.py
    ├── requester.py
    ├── utils.py
    └── verbose.py

tests/

README.md
CHANGELOG.md
CONTRIBUTING.md
LICENSE
pyproject.toml
```

---

# 🗺️ Roadmap

## ✅ v0.7.0 — Current Release

### Added

- Security Score (0–100) and Grade (A–F)
- Risk level and penalty breakdown
- Cookie analysis: Secure, HttpOnly, SameSite
- Stable rule IDs for findings
- Enhanced JSON reports with scan metadata
- Markdown report export (`--markdown`)
- HTML report export (`--html`)
- CLI `--score` option
- API score/grade/summary exposure
- Dashboard score panel and finding summaries

---

## ✅ v0.6.0

### Added

- Comprehensive `--verbose` reporting
- Scan Information, Target Information, Request Configuration,
  Connection Information, HTTP Response, Redirect Information,
  Response Headers, Security Headers, Missing/Present Security
  Headers, Information Leakage, Response Statistics,
  Findings Summary, Overall Assessment, End of Scan sections

---

## 🚀 v0.8.0 — Next

Planned features:

- Expanded unit test coverage (CLI / verbose rendering)
- GitHub Actions CI
- Documentation improvements
- Architecture improvements

---

## 🚀 v0.9.0

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

pip install -e .
```

Run:

```bash
argus-header https://example.com
```

Run verbose mode:

```bash
argus-header https://example.com --verbose
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