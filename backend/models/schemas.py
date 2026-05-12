from pydantic import BaseModel
from typing import Optional 
from enum import Enum

class InputType(str, Enum):
    ip = "ip"
    hash = "hash"
    domain = "domain"
    cve = "cve"

class RiskLevel(str, Enum):
    critical = "critical"
    high = "high"
    medium = "medium"
    low = "low"
    clean = "clean"
    unknown = "unknown"

class AnalyzeRequest(BaseModel):
    query: str

class Finding(BaseModel):
    title: str
    description: str
    source: str

class AnalyzeResponse(BaseModel):
    query: str
    input_type: InputType
    risk_level: RiskLevel
    risk_score: float | None = None
    summary: str
    findings: list[Finding]
    recommendations: list[str]
    raw_data: dict
    country: str | None = None