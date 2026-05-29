from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, Field


IOCType = Literal["ip", "domain", "url", "hash", "email", "unknown"]
Language = Literal["ar", "en"]


class AnalyzeRequest(BaseModel):
    indicators: str = Field(..., min_length=1)
    company_name: str = Field(default="Company")
    context: str = Field(default="")
    use_openai: bool = True
    language: Language = "ar"


class CaseTaskUpdate(BaseModel):
    id: int
    completed: bool


class CaseUpdateRequest(BaseModel):
    status: Literal["Open", "In Progress", "Containment", "Closed"] | None = None
    notes: str | None = None
    tasks: list[CaseTaskUpdate] = Field(default_factory=list)


class SourceVerdict(BaseModel):
    source: str
    status: str
    score: int = 0
    summary: str = ""
    raw: dict[str, Any] = Field(default_factory=dict)


class MitreTechnique(BaseModel):
    tactic: str
    technique_id: str
    technique: str
    confidence: str
    rationale: str


class IndicatorResult(BaseModel):
    value: str
    type: IOCType
    normalized_from: list[str] = Field(default_factory=list)
    occurrence_count: int = 1
    related_entities: dict[str, str] = Field(default_factory=dict)
    risk_score: int
    severity: Literal["Low", "Medium", "High", "Critical"]
    confidence: Literal["Low", "Medium", "High"] = "Low"
    source_agreement: dict[str, int] = Field(default_factory=dict)
    threat_labels: list[str] = Field(default_factory=list)
    verdicts: list[SourceVerdict]
    mitre: list[MitreTechnique]
    recommended_actions: list[str]


class ReportSummaries(BaseModel):
    executive: str
    operations: str
    technical: str


class AnalysisResult(BaseModel):
    id: str
    company_name: str
    language: Language = "ar"
    created_at: datetime
    indicators: list[IndicatorResult]
    summaries: ReportSummaries
    stats: dict[str, Any]
    case: dict[str, Any] = Field(default_factory=dict)
    exports: dict[str, str] = Field(default_factory=dict)
