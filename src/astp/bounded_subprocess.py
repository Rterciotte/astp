from __future__ import annotations

import hashlib
import os
import subprocess
from collections.abc import Callable
from dataclasses import dataclass

from astp.tool_output_guard import bound_tool_output
from astp.worker_command import CompiledWorkerCommand


@dataclass(frozen=True)
class BoundedProcessResult:
    exit_code: int
    stdout: bytes
    stderr: bytes
    output_sha256: str
    output_truncated: bool


ProcessRunner = Callable[..., subprocess.CompletedProcess[bytes]]


def run_bounded_subprocess(
    command: CompiledWorkerCommand,
    *,
    timeout_seconds: float,
    max_output_bytes: int,
    runner: ProcessRunner = subprocess.run,
) -> BoundedProcessResult:
    completed = runner(
        [command.executable, *command.argv],
        shell=False,
        capture_output=True,
        timeout=timeout_seconds,
        check=False,
        env={key: os.environ[key] for key in ("PATH", "LANG", "LC_ALL") if key in os.environ},
    )
    stdout = completed.stdout or b""
    stderr = completed.stderr or b""
    combined, guard = bound_tool_output(stdout + stderr, max_output_bytes)
    stdout_len = min(len(stdout), len(combined))
    bounded_stdout = combined[:stdout_len]
    bounded_stderr = combined[stdout_len:]
    return BoundedProcessResult(
        exit_code=completed.returncode,
        stdout=bounded_stdout,
        stderr=bounded_stderr,
        output_sha256=hashlib.sha256(combined).hexdigest(),
        output_truncated=guard.truncated,
    )
