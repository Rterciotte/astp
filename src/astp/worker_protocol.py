from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field


class WorkerOperation(StrEnum):
    BROWSER_NAVIGATE = "browser.navigate"
    BROWSER_DOM_SNAPSHOT = "browser.dom_snapshot"
    BROWSER_SCREENSHOT = "browser.screenshot"
    NMAP_DISCOVERY = "external.nmap.discovery"
    NUCLEI_SAFE = "external.nuclei.safe"
    ZAP_BASELINE = "external.zap.baseline"


class WorkerRequest(BaseModel):
    model_config = ConfigDict(frozen=True)

    request_id: str
    permit_id: str
    action_id: str
    engagement_id: str
    operation: WorkerOperation
    target: str
    timeout_seconds: float = Field(default=30.0, gt=0, le=300)
    max_output_bytes: int = Field(default=1_048_576, ge=1024, le=16_777_216)
    arguments: tuple[str, ...] = Field(default_factory=tuple)


class WorkerReceipt(BaseModel):
    model_config = ConfigDict(frozen=True)

    request_id: str
    permit_id: str
    action_id: str
    operation: WorkerOperation
    exit_code: int | None = None
    output_sha256: str | None = None
    output_truncated: bool = False
    network_io_performed: bool = False
    permit_consumed_before_io: bool = False
    redirect_target: str | None = None
    evidence_id: str | None = None


def allowed_arguments(operation: WorkerOperation) -> tuple[str, ...]:
    mapping = {
        WorkerOperation.BROWSER_NAVIGATE: (),
        WorkerOperation.BROWSER_DOM_SNAPSHOT: (),
        WorkerOperation.BROWSER_SCREENSHOT: (),
        WorkerOperation.NMAP_DISCOVERY: ("tcp-connect-bounded", "service-detection-bounded"),
        WorkerOperation.NUCLEI_SAFE: ("info", "low-impact"),
        WorkerOperation.ZAP_BASELINE: ("passive-baseline",),
    }
    return mapping[operation]


def validate_worker_request(request: WorkerRequest) -> tuple[str, ...]:
    blockers: list[str] = []
    if not request.permit_id.strip() or not request.action_id.strip():
        blockers.append("worker request requires permit and action bindings")
    allowed = allowed_arguments(request.operation)
    if request.arguments and any(item not in allowed for item in request.arguments):
        blockers.append("worker request contains a non-allowlisted argument")
    return tuple(blockers)
