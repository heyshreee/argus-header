# Changelog

## [0.8.0] - 2026-09-03

### Added

- Deep security rules engine with 9 rule families (CSP, CORS, Cookies, HSTS, Cache, Cross-Origin, Referrer, Permissions, Base Headers)
- Security Score Engine 2.0 — weighted, category-aware scoring with A+ grade
- YAML configuration support (`--config .argus.yml`)
- SARIF 2.1.0 report export (`--sarif`)
- Cyberpunk-style HTML report export (`--report`)
- `diff` command to compare two scan reports (`argus-header diff before.json after.json`)
- CI/CD gating via `--fail-on` and `--min-score`
- JSON report to stdout when `--json` given without a filename
- SARIF report to stdout when `--sarif` given without a filename
- PyYAML dependency

### Changed

- Rewrote CLI for the v0.8 scan pipeline
- Rewrote output renderers (JSON, SARIF, HTML, terminal)
- Rewrote analyzer layer as modular per-header analyzers
- New `engine/`, `analyzers/`, `output/`, `diff/`, `models/` package structure
- Sorted severity into CRITICAL/HIGH/MEDIUM/LOW (added CRITICAL level)
- Expanded test coverage across analyzers, engine, reports and diff

---

## [0.7.0] - 2026-08-22

### Added

- Security Score from 0–100.
- Security Grade from A–F.
- Cookie security analysis for Secure, HttpOnly, and SameSite.
- Stable rule IDs for findings.
- Enhanced JSON security reports.
- Markdown report export.
- HTML report export.
- CLI `--score` option.
- CLI `--markdown` report export.
- CLI `--html` report export.
- API exposure of score, grade, risk level, and finding summaries.
- Dashboard display for security score and finding summaries.

### Changed

- JSON reports now contain structured scan metadata.
- JSON reports now use ISO timestamps instead of the `Now` placeholder.
- Findings now include stable rule identifiers.

### Security

- HTML report output escapes untrusted response data before rendering.

---

## [Unreleased]

---

## [0.6.0] - 2026-08-02

### Added

- Comprehensive `--verbose` reporting mode.
- Scan Information section.
- Target Information section.
- Request Configuration section.
- Connection Information section.
- HTTP Response section.
- Redirect Information section.
- Response Headers section.
- Security Headers section.
- Missing Security Headers section.
- Present Security Headers section.
- Information Leakage section.
- Response Statistics section.
- Findings Summary section.
- Overall Assessment section.
- End of Scan section.

### Improved

- Better terminal output organization.
- Enhanced user experience for detailed analysis.