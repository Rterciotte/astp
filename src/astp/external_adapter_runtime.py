from __future__ import annotations

import hashlib
import shutil
from collections.abc import Callable

from pydantic import BaseModel, ConfigDict, Field

from astp.external_adapter_contracts import (
    ExternalAdapterContract,
    builtin_external_adapter_contracts,
)


class ExternalAdapterJob(BaseModel):
    model_config = ConfigDict(frozen=True)

    id: str
    adapter_id: str
    target: str
    mode: str
    arguments: tuple[str, ...] = Field(default_factory=tuple)
    permit_id: str
    action_id: str


class ExternalAdapterReceipt(BaseModel):
    model_config = ConfigDict(frozen=True)

    job_id: str
    adapter_id: str
    exit_code: int
    stdout_sha256: str
    stderr_sha256: str
    execution_performed: bool = True


def adapter_runtime_available(contract: ExternalAdapterContract) -> bool:
    return shutil.which(contract.executable) is not None


def build_external_adapter_job(
    adapter_id: str,
    target: str,
    mode: str,
    *,
    permit_id: str,
    action_id: str,
) -> ExternalAdapterJob:
    contracts = {item.id: item for item in builtin_external_adapter_contracts()}
    contract = contracts.get(adapter_id)
    if contract is None:
        raise ValueError("unknown external adapter")
    if mode not in contract.allowed_modes:
        raise ValueError("external adapter mode is not allowlisted")
    digest = hashlib.sha256(
        f"{adapter_id}|{target}|{mode}|{permit_id}|{action_id}".encode()
    ).hexdigest()[:16]
    return ExternalAdapterJob(
        id=f"adapter-job-{digest}",
        adapter_id=adapter_id,
        target=target,
        mode=mode,
        permit_id=permit_id,
        action_id=action_id,
    )


AdapterRunner = Callable[[ExternalAdapterJob], tuple[int, bytes, bytes]]


def execute_external_adapter_job(
    job: ExternalAdapterJob,
    runner: AdapterRunner,
) -> ExternalAdapterReceipt:
    exit_code, stdout, stderr = runner(job)
    return ExternalAdapterReceipt(
        job_id=job.id,
        adapter_id=job.adapter_id,
        exit_code=exit_code,
        stdout_sha256=hashlib.sha256(stdout).hexdigest(),
        stderr_sha256=hashlib.sha256(stderr).hexdigest(),
    )
