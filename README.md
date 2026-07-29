# 🛡️ Argus Header

> Fast, lightweight HTTP security header analyzer built for developers, security engineers, and penetration testers.

![Python](https://img.shields.io/badge/Python-3.9+-blue.svg)
![Version](https://img.shields.io/badge/version-v0.5.0-orange.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)

Argus Header is a command-line tool that analyzes HTTP response headers and identifies common security misconfigurations, information leakage, and header-related best practice issues.

---

## ✨ Features

### HTTP Request Engine

- GET and HEAD request support
- Configurable request timeout
- Redirect support
- Retry mechanism for temporary failures
- Multiple URL scanning
- Parallel scanning

### Security Analysis

Detects missing security headers including:

- Content-Security-Policy (CSP)
- Strict-Transport-Security (HSTS)
- X-Frame-Options
- X-Content-Type-Options

### Information Disclosure Detection

Checks for exposed:

- Server
- X-Powered-By

### CORS Analysis

Detects:

- Access-Control-Allow-Origin: *

### Performance Checks

Checks:

- Cache-Control

### Reports

- Beautiful Rich CLI output
- JSON report export
- Severity levels
- Recommendations

---

# Installation

## From Source

```bash
git clone https://github.com/heyshreee/argus-header.git

cd argus-header

python -m venv .venv

source .venv/bin/activate
```

Windows

```powershell
.venv\Scripts\activate
```

Install

```bash
pip install -e .
```

---

## Verify Installation

```bash
argus-header --version
```

Expected output

```text
argus-header 0.5.0
```

---

# Usage

Basic scan

```bash
argus-header https://example.com
```

HEAD request

```bash
argus-header https://example.com --method HEAD
```

Custom timeout

```bash
argus-header https://example.com --timeout 5
```

Multiple URLs

```bash
argus-header https://google.com https://github.com --parallel
```

Disable redirects

```bash
argus-header https://example.com --no-redirect
```

Export JSON

```bash
argus-header https://example.com --json report.json
```

Help

```bash
argus-header --help
```

---

# Command Line Options

| Option | Description |
|---------|-------------|
| --method | HTTP Method (GET / HEAD) |
| --timeout | Request timeout |
| --parallel | Scan multiple URLs concurrently |
| --json FILE | Save report as JSON |
| --no-redirect | Disable redirect following |
| --verbose | Verbose output |
| --version | Display version |
| --help | Show help |

---

# Example Output

```text
Target
https://example.com

Status
200

Headers Found
18

HIGH
Missing Content-Security-Policy

HIGH
Missing Strict-Transport-Security

MEDIUM
X-Powered-By Header Exposed

LOW
Missing Cache-Control
```

---

# Project Structure

```
argus-header/

src/
└── argus_header/
    ├── __init__.py
    ├── cli.py
    ├── requester.py
    ├── analyzer.py
    ├── reporter.py
    └── utils.py

tests/

README.md
LICENSE
pyproject.toml
```

---

# Current Checks

## Security Headers

- Content-Security-Policy
- Strict-Transport-Security
- X-Frame-Options
- X-Content-Type-Options

## Information Leakage

- Server
- X-Powered-By

## CORS

- Wildcard Access-Control-Allow-Origin

## Performance

- Cache-Control

---

# Roadmap

## v0.5.0 — Current Release

### Core Features

* HTTP GET & HEAD request support
* Configurable request timeout
* Redirect handling
* Retry mechanism
* Parallel URL scanning
* Rich CLI output
* JSON report export
* Security header detection
* Information leakage detection
* CORS wildcard analysis
* Cache-Control analysis
* PyPI-ready packaging

---

# Development

Clone

```bash
git clone https://github.com/heyshreee/argus-header.git
```

Install development version

```bash
pip install -e .
```

Run

```bash
argus-header https://example.com
```

---

# Contributing

Contributions are welcome.

1. Fork the repository
2. Create a feature branch

```bash
git checkout -b feature/my-feature
```

3. Commit

```bash
git commit -m "feat: add awesome feature"
```

4. Push

```bash
git push origin feature/my-feature
```

5. Open a Pull Request

---

# License

Released under the MIT License.

See LICENSE for details.

---

# Author

**Sriram**

GitHub

https://github.com/heyshreee

---

## Disclaimer

Argus Header is intended for defensive security, security auditing, learning, and authorized penetration testing only.

Only scan systems that you own or have explicit permission to assess.