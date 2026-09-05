from __future__ import annotations

from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field

from astp.runtime_specs import RuntimeSpec
from astp.worker_protocol import WorkerRequest, validate_worker_request


class WorkerSupervisorPlan(BaseModel):
    model_config = ConfigDict(frozen=True)

    runtime_id: str
    request_id: str
    command: tuple[str, ...] = Field(default_factory=tuple)
    shell: bool = False
    read_only_root: bool = True
    signing_key_mounts: tuple[str, ...] = Field(default_factory=tuple)
    network_enabled: bool = False
    ready_for_launch: bool = False
    blockers: tuple[str, ...] = Field(default_factory=tuple)


def build_worker_supervisor_plan(
    spec: RuntimeSpec,
    request: WorkerRequest,
    *,
    runtime_executable: str,
    permit_consumed: bool,
) -> WorkerSupervisorPlan:
    blockers = list(validate_worker_request(request))
    if not permit_consumed:
        blockers.append("execution permit must be consumed before worker launch")
    if spec.shell_allowed:
        blockers.append("runtime specification must prohibit shell execution")
    if spec.signing_keys_available:
        blockers.append("runtime specification must not expose signing keys")
    executable = str(Path(runtime_executable))
    if not executable.strip():
        blockers.append("runtime executable is required")
    return WorkerSupervisorPlan(
        runtime_id=spec.id,
        request_id=request.request_id,
        command=(executable, "--request-id", request.request_id),
        network_enabled=permit_consumed and not blockers,
        ready_for_launch=not blockers,
        blockers=tuple(blockers),
    )
