from __future__ import annotations

from pydantic import BaseModel, ConfigDict

from astp.local_qualification_lab import LocalQualificationLab
from astp.permit_consumption_proof import PermitConsumptionProof
from astp.runtime_resource_envelope import RuntimeResourceEnvelope
from astp.worker_protocol import WorkerRequest


class PhysicalDockerCommand(BaseModel):
    model_config = ConfigDict(frozen=True)
    argv: tuple[str, ...]
    network_capable: bool = False


def compile_hardened_offline_run(
    *, image_ref: str, request_path: str, resources: RuntimeResourceEnvelope
) -> PhysicalDockerCommand:
    if not image_ref.strip() or not request_path.strip():
        raise ValueError("image_ref and request_path are required")
    argv = (
        "docker",
        "run",
        "--rm",
        "--read-only",
        "--security-opt",
        "no-new-privileges:true",
        "--cap-drop",
        "ALL",
        "--network",
        "none",
        *resources.docker_argv(),
        "--tmpfs",
        "/tmp:rw,noexec,nosuid,size=64m",
        "--mount",
        f"type=bind,src={request_path},dst=/run/astp/request.json,readonly",
        image_ref,
    )
    return PhysicalDockerCommand(argv=argv)


def compile_authorized_lab_run(
    *,
    image_ref: str,
    request_path: str,
    resources: RuntimeResourceEnvelope,
    lab: LocalQualificationLab,
    worker_request: WorkerRequest,
    consumption: PermitConsumptionProof,
    qualification_probe: str | None = None,
) -> PhysicalDockerCommand:
    """Enable only the fixed lab network after exact permit consumption proof."""
    if worker_request.engagement_id != lab.engagement_id:
        raise ValueError("worker request is not bound to the qualification engagement")
    if worker_request.target == lab.service_name:
        pass
    else:
        lab.authorize_url(worker_request.target)
    if consumption.lifecycle_status.value != "consumed":
        raise ValueError("permit consumption proof is not consumed")
    if consumption.engagement_id != worker_request.engagement_id:
        raise ValueError("consumption proof engagement mismatch")
    if consumption.permit_id != worker_request.permit_id:
        raise ValueError("consumption proof permit mismatch")
    if consumption.action_id != worker_request.action_id:
        raise ValueError("consumption proof action mismatch")
    if consumption.target != worker_request.target:
        raise ValueError("consumption proof target mismatch")

    argv = list(
        compile_hardened_offline_run(
            image_ref=image_ref,
            request_path=request_path,
            resources=resources,
        ).argv
    )
    network_index = argv.index("none")
    argv[network_index] = lab.docker_network
    env_argv = ["--env", f"ASTP_ALLOWED_TARGET={lab.service_name}"]
    if qualification_probe is not None:
        if qualification_probe != "bounded-output-v1":
            raise ValueError("unsupported physical qualification probe")
        env_argv.extend(("--env", f"ASTP_QUALIFICATION_PROBE={qualification_probe}"))
    argv[2:2] = tuple(env_argv)
    return PhysicalDockerCommand(argv=tuple(argv), network_capable=True)
