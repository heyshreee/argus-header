import time
import uuid

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware

from argus_header import __version__
from argus_header.analyzer import analyze_headers
from argus_header.reporter import build_json_report
from argus_header.requester import fetch_headers
from argus_header.schemas import (
    AnalysisSummary,
    AnalyzeRequest,
    AnalyzeResponse,
    ScoreResult,
)
from argus_header.scorer import calculate_score

app = FastAPI(
    title="HTTP Header Analyzer API",
    description="An API to fetch and analyze HTTP headers for security issues.",
    version=__version__,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # frontend access
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


def _analyze(url: str) -> AnalyzeResponse:
    """Shared scan pipeline: fetch → analyze → score → canonical report."""
    start = time.perf_counter()

    response_data = fetch_headers(url)

    if not response_data.get("success"):
        raise HTTPException(
            status_code=400,
            detail=response_data.get("error", "Failed to fetch headers."),
        )

    findings = analyze_headers(response_data)
    score = calculate_score(findings)

    report = build_json_report(
        response_data=response_data,
        findings=findings,
        score_data=score,
        scan_id=uuid.uuid4().hex[:8],
        target=str(url),
    )

    elapsed = round(time.perf_counter() - start, 4)

    return AnalyzeResponse(
        url=report["scan"]["final_url"] or report["scan"]["target"],
        status=report["scan"]["status"],
        headers=report["headers"],
        analysis=findings,
        score=ScoreResult(
            value=score["score"],
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
