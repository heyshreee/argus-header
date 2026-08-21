# Contributing to Argus Header

Thank you for your interest in contributing!

## Setup

Clone the repository:

```bash
git clone https://github.com/heyshreee/argus-header.git
cd argus-header
```

Create a virtual environment:

```bash
python -m venv .venv
```

Activate it:

Windows:

```powershell
.\.venv\Scripts\Activate.ps1
```

Linux / macOS:

```bash
source .venv/bin/activate
```

Install the package and development dependencies:

```bash
pip install -e .
pip install -r requirements-dev.txt
```

`requirements-dev.txt` includes: `build`, `twine`, `pytest`, `pytest-cov`, `ruff`, `black`, `mypy`.

---

## Running

Basic scan:

```bash
argus-header https://example.com
```

Security score and reports (v0.7.0):

```bash
argus-header https://example.com --score
argus-header https://example.com --json report.json --markdown report.md --html report.html
```

---

## Tests

All contributions must keep the test suite green:

```bash
pytest tests/ -v
```

With coverage:

```bash
pytest tests/ --cov=src/argus_header --cov-report=term-missing
```

Notes:

- New analyzer rules need a matching test in `tests/test_analyzer.py`.
- New scoring penalties need coverage in `tests/test_scorer.py`.
- Requester tests hit the live network (integration-style); don't be surprised if they take a few seconds.

---

## Code Quality Checks

Run all three before committing — CI-style hygiene:

```bash
ruff check src/ tests/
black src/ tests/
mypy src/
```

- **ruff** must pass with zero findings (do not add `# noqa` suppressions).
- **black** is the formatter of record; run it rather than hand-formatting.
- **mypy** must pass on `src/` with zero errors.

---

## Coding Style

- Follow PEP 8; black handles formatting.
- Keep functions small and focused.
- Add comments only where logic is non-obvious.
- Analyzer findings must carry a stable rule ID (`SEC-*`, `LEAK-*`, `CORS-*`, `PERF-*`, `COOKIE-*`) — never renumber existing IDs.
- Any new finding category needs an entry in the scorer's penalty table and in `docs/DOCUMENTATION.md` §6.

---

## Commit Messages

Use conventional commits:

```
feat: add verbose response headers
fix: handle redirect loop
docs: update README
refactor: simplify analyzer
chore: apply black formatting
release: v0.8.0
```

---

## Pull Requests

- Create a feature branch from `main` (`feat/my-feature`, `fix/my-bugfix`).
- Run tests, ruff, black, and mypy before pushing.
- Update documentation (`README.md`, `docs/DOCUMENTATION.md`, `CHANGELOG.md`) for user-visible changes.
- Submit a pull request with a clear description.

---

## Releases (maintainers)

1. Bump the version in `pyproject.toml` and `src/argus_header/__init__.py`.
2. Update `CHANGELOG.md`.
3. Clean build: `rm -rf build dist && python -m build`
4. Validate: `twine check dist/*`
5. Tag: `git tag -a vX.Y.Z -m "Argus Header vX.Y.Z" && git push origin vX.Y.Z`
6. Upload: `twine upload dist/*`
7. Verify a clean install: `pip install argus-header==X.Y.Z` in a fresh virtualenv.
