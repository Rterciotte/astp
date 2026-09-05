from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field

from astp.runtime_artifacts import RuntimeArtifact


class WorkerLaunchDecision(StrEnum):
    ALLOW = "allow"
    DENY = "deny"


class WorkerLaunchEnvelope(BaseModel):
    model_config = ConfigDict(frozen=True)

    runtime_id: str
    artifact_identity_hash: str
    engagement_id: str
    permit_id: str
    action_id: str
    capability_id: str
    target: str
    network_enabled: bool = False
    read_only_rootfs: bool = True
    shell_enabled: bool = False
    signing_keys_mounted: bool = False
    arbitrary_mounts: bool = False
    max_output_bytes: int = Field(default=1_048_576, ge=1024, le=16_777_216)


class WorkerLaunchAssessment(BaseModel):
    model_config = ConfigDict(frozen=True)

    decision: WorkerLaunchDecision
    blockers: tuple[str, ...] = Field(default_factory=tuple)


def evaluate_worker_launch(
    envelope: WorkerLaunchEnvelope, artifact: RuntimeArtifact
) -> WorkerLaunchAssessment:
    blockers: list[str] = []
    if envelope.runtime_id != artifact.runtime_id:
        blockers.append("runtime id does not match the immutable artifact")
    if envelope.artifact_identity_hash != artifact.identity_hash():
        blockers.append("artifact identity hash mismatch")
    if not artifact.digest_is_pinned:
        blockers.append("runtime artifact is not digest-pinned")
    if not envelope.permit_id.strip() or not envelope.action_id.strip():
        blockers.append("exact action permit binding is required")
    if envelope.capability_id not in artifact.capabilities:
        blockers.append("capability is not exported by this runtime artifact")
    if envelope.shell_enabled:
        blockers.append("worker shell execution is forbidden")
    if envelope.signing_keys_mounted:
        blockers.append("worker signing-key mounts are forbidden")
    if envelope.arbitrary_mounts:
        blockers.append("arbitrary worker mounts are forbidden")
    if not envelope.read_only_rootfs:
        blockers.append("worker root filesystem must be read-only")
    if envelope.network_enabled and not envelope.permit_id.strip():
        blockers.append("network cannot be enabled without a permit")
    return WorkerLaunchAssessment(
        decision=WorkerLaunchDecision.DENY if blockers else WorkerLaunchDecision.ALLOW,
        blockers=tuple(blockers),
    )
