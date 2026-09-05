from __future__ import annotations

from collections.abc import Callable

from astp.bounded_subprocess import BoundedProcessResult
from astp.worker_command import compile_worker_command
from astp.worker_protocol import (
    WorkerOperation,
    WorkerReceipt,
    WorkerRequest,
    validate_worker_request,
)

PermitConsumer = Callable[[str, str], None]
ToolRunner = Callable[[object], BoundedProcessResult]


def execute_external_runtime_candidate(
    request: WorkerRequest,
    *,
    consume: PermitConsumer,
    runner: Callable[..., BoundedProcessResult],
) -> WorkerReceipt:
    blockers = validate_worker_request(request)
    if blockers:
        raise ValueError("; ".join(blockers))
    if request.operation not in {
        WorkerOperation.NMAP_DISCOVERY,
        WorkerOperation.NUCLEI_SAFE,
        WorkerOperation.ZAP_BASELINE,
    }:
        raise ValueError("request is not an allowlisted external-tool operation")

    command = compile_worker_command(request)
    consume(request.permit_id, request.action_id)
    result = runner(
        command,
        timeout_seconds=request.timeout_seconds,
        max_output_bytes=request.max_output_bytes,
    )
    return WorkerReceipt(
        request_id=request.request_id,
        permit_id=request.permit_id,
        action_id=request.action_id,
        operation=request.operation,
        exit_code=result.exit_code,
        output_sha256=result.output_sha256,
        output_truncated=result.output_truncated,
        network_io_performed=True,
        permit_consumed_before_io=True,
    )
