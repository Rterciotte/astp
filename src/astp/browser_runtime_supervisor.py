from __future__ import annotations

from collections.abc import Callable

from pydantic import BaseModel, ConfigDict, Field

from astp.browser_runtime import BrowserObservation
from astp.worker_protocol import (
    WorkerOperation,
    WorkerReceipt,
    WorkerRequest,
    validate_worker_request,
)


class BrowserRuntimeReceipt(BaseModel):
    model_config = ConfigDict(frozen=True)

    worker_receipt: WorkerReceipt
    final_url: str
    dom_sha256: str | None = None
    screenshot_sha256: str | None = None
    blockers: tuple[str, ...] = Field(default_factory=tuple)


PermitConsumer = Callable[[str, str], None]
BrowserDriver = Callable[[WorkerRequest], BrowserObservation]


def execute_browser_runtime_candidate(
    request: WorkerRequest,
    *,
    consume: PermitConsumer,
    driver: BrowserDriver,
) -> BrowserRuntimeReceipt:
    blockers = list(validate_worker_request(request))
    if request.operation not in {
        WorkerOperation.BROWSER_NAVIGATE,
        WorkerOperation.BROWSER_DOM_SNAPSHOT,
        WorkerOperation.BROWSER_SCREENSHOT,
    }:
        blockers.append("request is not a bounded browser operation")
    if blockers:
        raise ValueError("; ".join(blockers))

    consume(request.permit_id, request.action_id)
    observation = driver(request)
    if observation.target != request.target:
        raise ValueError("browser evidence target does not match authorized target")
    if observation.redirect_observed and observation.final_url != request.target:
        raise ValueError("browser redirect requires a new authorization and permit")

    receipt = WorkerReceipt(
        request_id=request.request_id,
        permit_id=request.permit_id,
        action_id=request.action_id,
        operation=request.operation,
        network_io_performed=request.operation == WorkerOperation.BROWSER_NAVIGATE,
        permit_consumed_before_io=True,
        redirect_target=observation.final_url if observation.redirect_observed else None,
    )
    return BrowserRuntimeReceipt(worker_receipt=receipt, final_url=observation.final_url)
