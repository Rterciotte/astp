from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field

from astp.container_launch_policy import ContainerLaunchPlan
from astp.runtime_build_manifest import RuntimeBuildManifest


class DockerCommand(BaseModel):
    model_config = ConfigDict(frozen=True)
    argv: tuple[str, ...]
    network_capable: bool = False
    reasons: tuple[str, ...] = Field(default_factory=tuple)


def compile_build_command(manifest: RuntimeBuildManifest, *, tag: str) -> DockerCommand:
    if not tag.strip() or any(char.isspace() for char in tag):
        raise ValueError("docker tag must be nonblank and whitespace-free")
    argv = (
        "docker",
        "build",
        "--pull",
        "--file",
        manifest.dockerfile,
        "--tag",
        tag,
        *manifest.build_args,
        manifest.context_dir,
    )
    return DockerCommand(argv=argv)


def compile_inspect_digest_command(image_ref: str) -> DockerCommand:
    if not image_ref.strip():
        raise ValueError("image reference cannot be blank")
    return DockerCommand(
        argv=("docker", "image", "inspect", "--format", "{{json .RepoDigests}}", image_ref)
    )


def compile_run_command(plan: ContainerLaunchPlan, *, request_path: str) -> DockerCommand:
    if not plan.ready_for_launch:
        return DockerCommand(argv=(), reasons=plan.reasons)
    if not request_path.strip():
        raise ValueError("request path cannot be blank")
    argv = [
        "docker",
        "run",
        "--rm",
        "--read-only",
        "--security-opt",
        "no-new-privileges:true",
        "--cap-drop",
        "ALL",
        "--tmpfs",
        "/tmp:rw,noexec,nosuid,size=64m",
    ]
    if plan.policy.network_enabled:
        argv.extend(("--network", "bridge"))
    else:
        argv.extend(("--network", "none"))
    argv.extend(
        (
            "--mount",
            f"type=bind,src={request_path},dst=/run/astp/request.json,readonly",
            plan.image_reference,
            *plan.argv,
        )
    )
    return DockerCommand(argv=tuple(argv), network_capable=plan.policy.network_enabled)
