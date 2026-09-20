# Security Policy

## Supported Versions

Security fixes are applied to the latest stable release line only.

| Version | Status | Supported |
|---------|--------|-----------|
| 0.8.x   | Latest stable release | ✅ |
| < 0.8.0 | Historical | ❌ |

## Reporting a Vulnerability

**Please do not open a public GitHub issue for security vulnerabilities.**

Preferred channel:

1. Use GitHub's **private vulnerability reporting**:
   [heyshreee/argus-header → Security → Report a vulnerability](https://github.com/heyshreee/argus-header/security/advisories/new)
2. Or email **srishree0607@gmail.com** with subject `[argus-header] Security`.

### What to include

- Affected version (run `argus-header --version`), install source (PyPI / source / Docker)
- Component: CLI (`src/argus_header/`), REST API (`api.py`), dashboard (`frontend/`), packaging
- Clear reproduction steps or proof of concept
- Expected vs actual behavior
- Your assessment of severity/impact

### Response targets

| Stage | Target |
|-------|--------|
| Acknowledgement | within 72 hours |
| Initial assessment / triage | within 7 days |
| Fix or mitigation | best effort within 30 days for confirmed issues |

You will be kept informed at every stage and credited in the fix's changelog entry unless you prefer otherwise.

## Scope

**In scope**

- The installed CLI and its report exports (JSON / Markdown / HTML / SARIF rendering)
- The FastAPI service (`api.py`) when exposed by an operator
- The web dashboard under `frontend/`
- Dependency and supply-chain issues affecting the published PyPI package `argus-header`

**Deployment notes**

The API accepts only public HTTP(S) targets and does not follow redirects.
Set `ARGUS_ALLOWED_ORIGINS` to a comma-separated list of trusted dashboard
origins before deployment; the default permits only `http://localhost:3000`.
Keep standard network egress controls in place as defence in depth.

**Out of scope**

- Scanning targets you do not own or lack authorization for (the tool is
  for defensive security and authorized testing only — see the disclaimer
  in the README)
- Vulnerabilities requiring a malicious operator scanning their own machine
- Missing features or general hardening ideas (please use regular issues)

## Safe Harbor

We consider good-faith research following this policy to be authorized:
we will not pursue legal action against anyone who

- reports vulnerabilities through the channels above,
- avoids privacy violations, data destruction, and service degradation,
- gives us reasonable time to fix issues before any public disclosure.

## Disclosure Policy

Coordinated disclosure: once a fix is released, we publish a changelog
entry (and a GitHub Security Advisory where warranted) acknowledging the
reporter if desired.
