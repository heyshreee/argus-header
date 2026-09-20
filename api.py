import os
import time

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware

from argus_header import __version__
from argus_header.schemas import (
    AnalysisSummary,
    AnalyzeRequest,
    AnalyzeResponse,
    ScoreResult,
)
from argus_header.scanner import scan_target
from argus_header.url_safety import UnsafeTargetError, validate_public_http_url
from argus_header.utils import normalize_url


def _allowed_origins() -> list[str]:
    """Read the explicit browser origins allowed to call this API.

    Operators can set ``ARGUS_ALLOWED_ORIGINS`` to a comma-separated list.
    Keeping a small localhost default makes development convenient without
    publishing a credentialed wildcard CORS policy.
    """
    raw = os.getenv("ARGUS_ALLOWED_ORIGINS", "http://localhost:3000")
    return [origin.strip() for origin in raw.split(",") if origin.strip()]

app = FastAPI(
    title="HTTP Header Analyzer API",
    description="An API to fetch and analyze HTTP headers for security issues.",
    version=__version__,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=_allowed_origins(),
    allow_credentials=False,
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type"],
)


def _analyze(url: str) -> AnalyzeResponse:
    """Run the safe, v0.8 scan pipeline used by the CLI.

    Redirects are deliberately disabled for the API: a safe public URL must
    not be able to redirect the service to an internal address.
    """
    start = time.perf_counter()
    target = normalize_url(url)

    try:
        report = scan_target(
            target,
            follow_redirects=False,
            request_validator=validate_public_http_url,
        )
    except UnsafeTargetError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    if report.get("error"):
        raise HTTPException(
            status_code=400,
            detail=report["error"],
        )

    findings = [_api_finding(finding) for finding in report["findings"]]
    score = report["score"]

    elapsed = round(time.perf_counter() - start, 4)

    return AnalyzeResponse(
        url=report["scan"]["final_url"],
        status=report["scan"]["status"],
        headers=report["headers"],
        analysis=findings,
        score=ScoreResult(
            value=score["value"],
            grade=score["grade"],
            risk_level=score["risk_level"],
            penalty=score["penalty"],
        ),
        summary=AnalysisSummary(
            total_findings=len(findings),
            high=sum(1 for f in findings if f.get("severity") == "HIGH"),
            medium=sum(1 for f in findings if f.get("severity") == "MEDIUM"),
            low=sum(1 for f in findings if f.get("severity") == "LOW"),
        ),
        timing={"backend_seconds": elapsed},
    )


def _api_finding(finding: dict) -> dict:
    """Adapt the v0.8 finding schema to the established dashboard contract."""
    return {
        "id": finding.get("id", "ARGUS-UNKNOWN"),
        "category": finding.get("category", "General"),
        "issue": finding.get("title", finding.get("issue", "Finding")),
        "severity": finding.get("severity", "LOW"),
        "risk": finding.get("risk") or finding.get("impact") or "",
        "fix": finding.get("recommendation", finding.get("fix", "")),
    }


@app.get(
    "/analyze",
    response_model=AnalyzeResponse,
    summary="Fetch and analyze HTTP headers from a URL",
)
def analyze_url(url: str):
    return _analyze(url)


@app.post(
    "/analyze",
    response_model=AnalyzeResponse,
    summary="Fetch and analyze HTTP headers from a URL (POST)",
)
def analyze_url_post(payload: AnalyzeRequest):
    return _analyze(str(payload.url))
