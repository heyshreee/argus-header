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

Install dependencies:

```bash
pip install -e .
```

---

## Running

```bash
argus-header https://example.com
```

---

## Coding Style

- Follow PEP 8.
- Keep functions small and focused.
- Add comments where logic is non-obvious.
- Test changes before committing.

---

## Commit Messages

Examples:

```
feat: add verbose response headers
fix: handle redirect loop
docs: update README
refactor: simplify analyzer
```

---

## Pull Requests

- Create a feature branch.
- Test your changes.
- Update documentation if necessary.
- Submit a pull request with a clear description.