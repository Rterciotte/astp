from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field

from astp.runtime_image_lock import RuntimeImageLock


class ContainerLaunchPolicy(BaseModel):
    model_config = ConfigDict(frozen=True)

    read_only_root: bool = True
    no_new_privileges: bool = True
    drop_all_capabilities: bool = True
    shell_allowed: bool = False
    signing_key_mounts_allowed: bool = False
    arbitrary_mounts_allowed: bool = False
    network_enabled: bool = False
    tmpfs_paths: tuple[str, ...] = ("/tmp",)


class ContainerLaunchPlan(BaseModel):
    model_config = ConfigDict(frozen=True)

    runtime_id: str
    image_reference: str
    argv: tuple[str, ...]
    policy: ContainerLaunchPolicy
    ready_for_launch: bool
    reasons: tuple[str, ...] = Field(default_factory=tuple)


def build_container_launch_plan(
    lock: RuntimeImageLock,
    *,
    permit_consumed: bool,
    network_requested: bool,
) -> ContainerLaunchPlan:
    lock.validate_pinned()
    reasons: list[str] = []
    if network_requested and not permit_consumed:
        reasons.append("network cannot be enabled before exact permit consumption")
    policy = ContainerLaunchPolicy(network_enabled=network_requested and permit_consumed)
    return ContainerLaunchPlan(
        runtime_id=lock.runtime_id,
        image_reference=lock.image_reference,
        argv=(lock.expected_executable, "-m", "astp_worker"),
        policy=policy,
        ready_for_launch=not reasons,
        reasons=tuple(reasons),
    )
