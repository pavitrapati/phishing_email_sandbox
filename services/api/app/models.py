from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field

JobStatus = Literal["queued", "running", "completed", "failed", "timeout"]
Level = Literal["benign", "suspicious", "malicious"]


class Signature(BaseModel):
    id: str
    name: str
    severity: int = Field(ge=0, le=100)
    description: str
    evidence: list[str] = []


class Verdict(BaseModel):
    score: int = Field(ge=0, le=100)
    level: Level
    confidence: float = Field(ge=0.0, le=1.0)
    summary: str
    top_reasons: list[str] = []


class FileInfo(BaseModel):
    name: str
    size: int
    family: str
    label: str
    md5: str
    sha1: str
    sha256: str
    entropy: float
    extension: str = ""
    extension_mismatch: str | None = None
    filename_flags: list[str] = []


class IOCs(BaseModel):
    urls: list[str] = []
    domains: list[str] = []
    ips: list[str] = []
    emails: list[str] = []


class NetworkActivity(BaseModel):
    dns_queries: list[dict[str, Any]] = []
    http_requests: list[dict[str, Any]] = []
    tcp_sessions: list[dict[str, Any]] = []
    connect_attempts: list[dict[str, Any]] = []
    contacted_hosts: list[str] = []


class JobCreated(BaseModel):
    job_id: str
    status: JobStatus
    poll: str


class Report(BaseModel):
    schema_version: str = "1.0"
    job_id: str
    status: JobStatus
    created_at: str
    finished_at: str | None = None
    duration_seconds: float | None = None

    file: FileInfo | None = None
    verdict: Verdict | None = None
    signatures: list[Signature] = []
    iocs: IOCs = IOCs()
    network: NetworkActivity = NetworkActivity()

    static: dict[str, Any] = {}
    dynamic: dict[str, Any] = {}

    llm_summary: str = ""
    errors: list[dict[str, Any]] = []
    engine: dict[str, Any] = {}
