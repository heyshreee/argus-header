# Changelog

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