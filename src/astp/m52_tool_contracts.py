from __future__ import annotations

from enum import StrEnum
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict, Field, model_validator


class ToolEngine(StrEnum):
    NUCLEI = "nuclei"
    ZAP = "zap"
    DALFOX = "dalfox"
    FFUF = "ffuf"
    SQLMAP = "sqlmap"
    PLAYWRIGHT = "playwright"


class BoundedToolJob(BaseModel):
    model_config = ConfigDict(frozen=True)
    engine: ToolEngine
    profile: str
    target: str
    permit_id: str
    action_id: str
    max_requests: int = Field(ge=1, le=100)
    max_concurrency: int = Field(ge=1, le=4)
    rate_per_second: float = Field(gt=0, le=5)
    timeout_seconds: int = Field(ge=1, le=300)
    parameter: str | None = None
    template_ids: tuple[str, ...] = ()
    wordlist: tuple[str, ...] = ()
    identity_ref: str | None = None

    @model_validator(mode="after")
    def validate_bounded_job(self) -> BoundedToolJob:
        parsed = urlsplit(self.target)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            raise ValueError("tool target must be an exact absolute HTTP(S) URL")
        if parsed.username or parsed.password:
            raise ValueError("credentials may not be embedded in targets")
        if not self.permit_id or not self.action_id:
            raise ValueError("tool job requires permit and action bindings")
        if self.engine is ToolEngine.SQLMAP and not self.parameter:
            raise ValueError("sqlmap requires one explicitly selected parameter")
        if self.engine is ToolEngine.FFUF and (not self.wordlist or len(self.wordlist) > 50):
            raise ValueError("ffuf requires an ASTP-generated wordlist of at most 50 entries")
        return self


_PROFILES = {
    ToolEngine.NUCLEI: {
        "passive-info",
        "exposure-safe",
        "misconfiguration-safe",
        "cve-readonly-safe",
        "dast-safe-active",
    },
    ToolEngine.ZAP: {"passive-field"},
    ToolEngine.DALFOX: {
        "parameter-preflight",
        "reflected-bounded",
        "dom-analysis",
        "stored-or-blind",
    },
    ToolEngine.FFUF: {"discovery-bounded"},
    ToolEngine.SQLMAP: {"detect-bounded"},
    ToolEngine.PLAYWRIGHT: {
        "auth-map",
        "session-rotation",
        "logout-invalidation",
        "oauth-state",
        "mfa-workflow",
    },
}


def compile_tool_argv(job: BoundedToolJob) -> tuple[str, ...]:
    if job.profile not in _PROFILES[job.engine]:
        raise ValueError("unsupported bounded tool profile")
    common_rate = str(job.rate_per_second)
    if job.engine is ToolEngine.NUCLEI:
        if not job.template_ids:
            raise ValueError("nuclei requires classified template IDs")
        return (
            "nuclei",
            "-u",
            job.target,
            "-jsonl",
            "-silent",
            "-rl",
            common_rate,
            "-c",
            str(job.max_concurrency),
            "-timeout",
            str(job.timeout_seconds),
            "-id",
            ",".join(job.template_ids),
        )
    if job.engine is ToolEngine.ZAP:
        return (
            "zap-baseline.py",
            "-t",
            job.target,
            "-J",
            "/tmp/report.json",
            "-m",
            str(max(1, job.timeout_seconds // 60)),
            "-I",
        )
    if job.engine is ToolEngine.DALFOX:
        return (
            "dalfox",
            "url",
            job.target,
            "--format",
            "json",
            "--worker",
            str(job.max_concurrency),
            "--timeout",
            str(job.timeout_seconds),
            "--only-poc",
            "r",
        )
    if job.engine is ToolEngine.FFUF:
        return (
            "ffuf",
            "-u",
            job.target.rstrip("/") + "/FUZZ",
            "-w",
            "/run/astp/wordlist.txt",
            "-json",
            "-rate",
            common_rate,
            "-t",
            str(job.max_concurrency),
        )
    if job.engine is ToolEngine.SQLMAP:
        return (
            "sqlmap",
            "-u",
            job.target,
            "-p",
            job.parameter or "",
            "--batch",
            "--level=1",
            "--risk=1",
            "--threads=1",
            "--stop-fail",
            "--output-dir=/tmp/sqlmap",
        )
    return ("node", "/worker/field.js", "--target", job.target, "--profile", job.profile)


def reject_arbitrary_arguments(arguments: tuple[str, ...]) -> None:
    if arguments:
        raise ValueError("arbitrary worker arguments are not accepted")
