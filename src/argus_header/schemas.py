from pydantic import BaseModel, HttpUrl


class AnalyzeRequest(BaseModel):
    url: HttpUrl


class ScoreResult(BaseModel):
    value: int
    grade: str
    risk_level: str
    penalty: int


class Finding(BaseModel):
    id: str
    category: str
    issue: str
    severity: str
    risk: str
    fix: str


class AnalysisSummary(BaseModel):
    total_findings: int
    high: int
    medium: int
    low: int


class AnalyzeResponse(BaseModel):
    url: str
    status: int
    headers: dict[str, str]
    analysis: list[Finding]
    score: ScoreResult
    summary: AnalysisSummary
    timing: dict[str, float]
