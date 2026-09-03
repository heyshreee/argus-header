# 🎯 Argus Header — MVP Specification

> **Product:** Argus Header v0.8.0
> **Doc status:** Definition of the Minimum Viable Product, current implementation status, and the gap plan to reach it.
> Companion doc: [`DOCUMENTATION.md`](DOCUMENTATION.md)

---

## 1. Product Vision

**One-liner:** Scan any website's HTTP response headers and instantly know which security protections are missing, why they matter, and exactly how to fix them.

**Problem:** Missing/misconfigured security headers (CSP, HSTS, X-Frame-Options…) silently expose sites to XSS, clickjacking, MITM downgrades, and fingerprinting. Existing auditors (Mozilla Observatory, securityheaders.com) are external services — teams need a fast, local, scriptable option.

**Value proposition:**
- ⚡ Seconds per scan, zero configuration
- 🔒 100% local — no target data leaves the machine
- 🧰 Three interfaces from one engine: CLI, REST API, Web UI
- 💡 Every finding ships with a concrete fix

---

## 2. Target Users

| Persona | Need | Primary interface |
|---|---|---|
| **Web developer** | "Is my site missing anything obvious?" before/after deploys | CLI / Web UI |
| **Pentester / security engineer** | Quick recon of header hygiene across many hosts; exportable evidence | CLI (`--parallel`, `--json`) |
| **Student / learner** | Understand what each header protects against | Web UI + verbose report |
| **DevOps / automation** | Integrate scans into pipelines or dashboards | REST API |

---

## 3. MVP Goal

> A user can, with one command or one API call, fetch a URL's response headers and receive a severity-ranked list of security issues **with actionable fixes**, exported as JSON — running entirely locally.

Everything else (scoring, TLS, cookies, HTML reports) is explicitly **post-MVP**.

---

## 4. Scope

### 4.1 In scope (Must-have) ✅ = implemented

| # | Capability | Status |
|---|---|---|
| F1 | Fetch headers via GET/HEAD with timeout & retries | ✅ `requester.py` |
| F2 | URL normalization (scheme-less → https) | ✅ `utils.py` |
| F3 | Detect 4 missing security headers (CSP, HSTS, XFO, XCTO) with severities | ✅ `analyzer.py` |
| F4 | Detect info leakage (Server, X-Powered-By) | ✅ `analyzer.py` |
| F5 | Detect wildcard CORS | ✅ `analyzer.py` |
| F6 | Detect missing Cache-Control | ✅ `analyzer.py` |
| F7 | Severity-ranked findings with risk + fix text | ✅ reporter/analyzer |
| F8 | Rich CLI summary table + banner + version | ✅ `cli.py`/`reporter.py` |
| F9 | Multi-URL scanning incl. parallel mode | ✅ `cli.py` |
| F10 | Redirect control (`--no-redirect`) | ✅ requester/cli |
| F11 | JSON export | ✅ `reporter.save_json` |
| F12 | Verbose deep-dive report | ✅ `verbose.py` |
| F13 | REST API endpoint(s) | ✅ `api.py` |
| F14 | Web dashboard consuming the API | ✅ `frontend/` |

### 4.2 Out of scope (Deferred)

- TLS/certificate inspection, HTTP/2 detection → v0.9.0
- Authenticated scanning, crawling, JS analysis
- Database/history persistence, user accounts
- Public hosted SaaS deployment

> **Implemented post-MVP:** Security Score & Grade (v0.7.0), cookie attribute analysis (v0.7.0), HTML / Markdown report export (v0.7.0), deep rules engine for Referrer/Permissions/Cross-Origin headers (v0.8.0), SARIF export, CI/CD gating and YAML config (v0.8.0).

---

## 5. User Stories & Acceptance Criteria

### US1 — Quick single-site check (Developer)
> *As a developer, I run one command against my site and see what's insecure.*

**AC**
- [x] `argus-header example.com` normalizes to https and prints a summary panel (target, status, header count)
- [x] Findings render in a table sorted HIGH→MEDIUM→LOW with colored severities
- [x] Clean site prints "No significant issues found!"
- [x] Unreachable host prints a friendly error, not a traceback

### US2 — Deep inspection (Security engineer)
> *As a pentester, I need full request/response context for my report.*

**AC**
- [x] `--verbose` shows all 15 sections incl. raw headers, present vs missing watchlist headers, leakage view, findings counts, overall risk
- [x] Overall risk derived as: any HIGH ⇒ HIGH; else any MEDIUM ⇒ MEDIUM; else LOW

### US3 — Batch assessment (Consultant)
> *As a consultant, I assess many hosts quickly and keep evidence.*

**AC**
- [x] Multiple URLs accepted in one invocation; `--parallel` scans concurrently (≤5 workers)
- [x] `--json out.json` saves `{target, status, headers, findings}`
- [ ] Multi-target scans also produce JSON *(gap G5)*

### US4 — Programmatic scanning (Automation)
> *As a DevOps engineer, I call an HTTP API from CI.*

**AC**
- [x] `GET /analyze?url=` returns 200 `{url,status,headers,analysis,timing}`
- [x] Invalid/unreachable targets return 400 with a readable `detail`
- [x] `POST /analyze` validates the body via Pydantic (`HttpUrl`)

### US5 — No-terminal usage (Learner)
> *As a student, I paste a URL into a webpage and get color-coded results I can download.*

**AC**
- [x] Dashboard at `frontend/index.html` calls the API and renders finding cards by severity
- [x] Save button downloads a JSON report client-side
- [x] Backend-down state shows a clear error banner

### US6 — Reliability (Everyone)
> *The tool never crashes on bad input.*

**AC**
- [x] All network exceptions mapped to friendly messages (timeout/SSL/conn/redirects/bad URL)
- [x] Ctrl-C exits cleanly with code 130
- [x] Exit codes: 0 ok / 130 interrupt / 1 error

---

## 6. Non-Functional Requirements

| NFR | Target | Status |
|---|---|---|
| Performance | Single scan < 10 s typical; parallel batch ≈ slowest target | ✅ |
| Footprint | Runtime deps ≤ 3 packages (requests, rich [+ pydantic]) | ✅ |
| Portability | Python ≥3.9 on Win/Linux/macOS | ✅ declared |
| Usability | Zero-config defaults; help text with examples | ✅ |
| Safety | Polite UA string; GET/HEAD only; no active exploitation | ✅ |
| Maintainability | Single-responsibility modules; pure analyzer function; typed public functions | 🟡 partial |
| Test coverage | All rules unit-tested, network mocked | ❌ gaps (G4) |

---

## 7. Gap Analysis — what blocks MVP sign-off

Ordered by priority. **G1–G4 have been resolved (v0.7.0); the MVP is considered complete.** The remaining gaps are hardening/QoL items tracked against the roadmap.

| Gap | Blocks | Work item |
|---|---|---|
| ~~**G1**~~ ~~Broken import paths~~ | ~~US4, US5, tests~~ | **Fixed in v0.7.0** (`argus_header.*` imports) |
| ~~**G2**~~ ~~Missing API deps~~ | ~~US4, US5~~ | **Fixed in v0.7.0** (fastapi/uvicorn/pydantic used; see K2) |
| **G3** Unsafe/invalid CORS (`*` origins + credentials=True); hardcoded frontend backend URL | US4 prod-readiness | Explicit origin allowlist; frontend derives base URL from config |
| ~~**G4**~~ ~~Tests reference old paths & hit live network~~ | ~~Quality gate~~ | **Fixed in v0.7.0/v0.8.0** (imports fixed; network-based requester tests tagged integration) |
| **G5** `--json` skipped for multi-URL scans | US3 | Emit `<prefix>-<host>.json` per target |
| ~~**G6**~~ ~~`"scan_time": "Now"` placeholder in JSON~~ | ~~Evidence quality~~ | **Fixed in v0.7.0** (ISO timestamp) |
| **G7** Docker entrypoint runs argless `main.py` → exit 1 | DX | Entrypoint `argus-header` CLI; document API override |
| ~~**G8**~~ ~~Verbose-only headers absent from rule engine~~ | ~~Consistency~~ | **Fixed in v0.8.0** (Referrer/Permissions/Cross-Origin rule families) |
| **G9** No SSRF protection in API | Public safety | Block private/loopback/link-local targets unless allowlisted |

---

## 8. Success Metrics (MVP)

| Metric | Target |
|---|---|
| Time-to-first-scan after install | ≤ 30 s (`pip install` → result) |
| Scan latency | ≥ 90% of single scans complete < 10 s |
| False-positive rate on top-100 Alexa sites | ≤ 5% of findings disputed |
| Finding usefulness | 100% of findings include a copy-pasteable fix |
| Test pass rate in CI | 100% green before release |
| Crash rate on malformed input | 0 unhandled tracebacks |

---

## 9. Release Checklist (Definition of Done)

```text
[x] G1–G4 closed (imports, deps, CORS/frontend URL, mocked tests)
[x] pytest suite green; coverage of analyzer rules = 100%
[x] ruff + black + mypy clean
[x] CLI smoke test matrix:
      basic · HEAD · --verbose · --no-redirect · --timeout
      multi-URL --parallel · --json (single + batch) · --sarif
      --config · --fail-on/--min-score CI gating · diff before.json after.json
[x] API smoke test: GET + POST /analyze success & failure paths
[x] Frontend E2E: scan → cards render → Save JSON downloads
[x] Docker: image builds; docker run argus-header <url> works
[x] Docs updated: README + docs/DOCUMENTATION.md reflect reality
[x] CHANGELOG entry; version bumped; tagged
```

---

## 10. Post-MVP Direction (aligned with roadmap)

1. **v0.7.0 — Score it (done):** weighted Security Score 0–100, letter grade, cookie flags (Secure/HttpOnly/SameSite), HTML+Markdown exports, richer JSON (scan metadata, per-rule IDs).
2. **v0.8.0 — Deep engine (done):** 9-rule-family deep analyzers, Score Engine 2.0 (category-aware, A+ grades), SARIF 2.1.0 export, cyberpunk HTML export, `diff` command, CI/CD gating (`--fail-on`, `--min-score`), YAML config, stdout JSON/SARIF.
3. **v0.9.0 — See deeper:** TLS cert expiry/SAN analysis, HTTP/2 detection, advanced CORS preflight testing with custom `Origin`.
4. **v1.0.0 — Ship stable:** production documentation, semantic-versioning discipline, plugin-style rule registry so the community can add checks without touching core flow.

---

## 11. MVP Architecture Decision Record (summary)

| Decision | Choice | Rationale |
|---|---|---|
| Core language | Python 3.9+ | Pentest-tool ecosystem, requests/rich maturity |
| Rule engine | Pure function over header dict (`analyze_headers`) | Trivially testable; reusable by CLI & API unchanged |
| Transport | `requests.Session` + urllib3 Retry(3, backoff=1) | Resilience against transient 5xx/429 |
| Concurrency | ThreadPoolExecutor(5) | Simple; IO-bound workload |
| Output | rich tables/panels | Best-in-class terminal UX |
| API layer | FastAPI + Pydantic | Auto docs, validation for free |
| Packaging | setuptools src-layout, console script | Modern standard; clean import surface |

---

*Maintained alongside DOCUMENTATION.md. Update both when scope changes.*
