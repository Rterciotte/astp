from __future__ import annotations

from collections.abc import Callable

from astp.browser_runtime import BrowserObservation
from astp.worker_protocol import (
    WorkerOperation,
    WorkerReceipt,
    WorkerRequest,
    validate_worker_request,
)

PermitConsumer = Callable[[str, str], None]
BrowserDriver = Callable[[WorkerRequest], BrowserObservation]


def execute_browser_protocol_worker(
    request: WorkerRequest,
    *,
    consume: PermitConsumer,
    driver: BrowserDriver,
) -> WorkerReceipt:
    blockers = validate_worker_request(request)
    if blockers:
        raise ValueError("; ".join(blockers))
    if request.operation not in {
        WorkerOperation.BROWSER_NAVIGATE,
        WorkerOperation.BROWSER_DOM_SNAPSHOT,
        WorkerOperation.BROWSER_SCREENSHOT,
    }:
        raise ValueError("request is not a bounded browser operation")
    consume(request.permit_id, request.action_id)
    observation = driver(request)
    if observation.target != request.target:
        raise ValueError("browser evidence target does not match authorized target")
    if observation.redirect_observed and observation.final_url != request.target:
        raise ValueError("browser redirect requires reauthorization")
    return WorkerReceipt(
        request_id=request.request_id,
        permit_id=request.permit_id,
        action_id=request.action_id,
        operation=request.operation,
        network_io_performed=request.operation == WorkerOperation.BROWSER_NAVIGATE,
        permit_consumed_before_io=True,
        redirect_target=observation.final_url if observation.redirect_observed else None,
    )
