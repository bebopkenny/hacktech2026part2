"""
Pydantic schemas — single source of truth for request/response shapes.
"""
from pydantic import BaseModel


class ScanRequest(BaseModel):
    url: str
    pat: str | None = None  # GitHub PAT for private repos


class Finding(BaseModel):
    rule_id: str
    file: str
    line: int
    matched_code: str
    exploitable: bool
    confidence: str          # high | medium | low
    taint_path: str | None   # "source (file:line) → sink (file:line)"
    auth_gap: str | None
    exploit_steps: list[str]
    severity: str            # critical | high | medium | low
    fix: str


class ScanResult(BaseModel):
    scan_id: str
    status: str
    progress: str | None
    raw_count: int           # all Semgrep findings
    confirmed_count: int     # subset AI deemed exploitable
    findings: list[Finding]
