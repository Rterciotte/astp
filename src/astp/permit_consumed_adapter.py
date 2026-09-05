from __future__ import annotations

from collections.abc import Callable

from pydantic import BaseModel, ConfigDict

from astp.external_adapter_runtime import ExternalAdapterJob, ExternalAdapterReceipt


class AdapterExecutionGuard(BaseModel):
    model_config = ConfigDict(frozen=True)
    permit_id: str
    action_id: str
    consumed: bool = False


PermitConsumer = Callable[[str, str], None]
AdapterRunner = Callable[[ExternalAdapterJob], tuple[int, bytes, bytes]]


def execute_permit_consumed_adapter(
    job: ExternalAdapterJob,
    *,
    consume: PermitConsumer,
    runner: AdapterRunner,
) -> ExternalAdapterReceipt:
    if not job.permit_id or not job.action_id:
        raise ValueError("adapter job requires exact permit and action binding")
    consume(job.permit_id, job.action_id)
    exit_code, stdout, stderr = runner(job)
    import hashlib

    return ExternalAdapterReceipt(
        job_id=job.id,
        adapter_id=job.adapter_id,
        exit_code=exit_code,
        stdout_sha256=hashlib.sha256(stdout).hexdigest(),
        stderr_sha256=hashlib.sha256(stderr).hexdigest(),
    )
