from pydantic import BaseModel, HttpUrl
from typing import Dict, List

class AnalysisSummary(BaseModel):
    total_checked: int
    missing: int
    risk_level: str

class AnalysisResult(BaseModel):
    summary: AnalysisSummary
    details: List[Dict]

class AnalyzeRequest(BaseModel):
    url: HttpUrl