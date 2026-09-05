from __future__ import annotations

from collections.abc import Callable

from astp.bounded_subprocess import BoundedProcessResult, run_bounded_subprocess
from astp.worker_command import compile_worker_command
from astp.worker_protocol import WorkerReceipt, WorkerRequest

PermitConsumer = Callable[[str, str], None]
ProcessExecutor = Callable[..., BoundedProcessResult]


def execute_tool_worker(
    request: WorkerRequest,
    *,
    consume: PermitConsumer,
    executor: ProcessExecutor = run_bounded_subprocess,
) -> WorkerReceipt:
    command = compile_worker_command(request)
    consume(request.permit_id, request.action_id)
    result = executor(
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
