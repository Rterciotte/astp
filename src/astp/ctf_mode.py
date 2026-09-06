from __future__ import annotations

import hashlib
from enum import Enum
from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field, field_validator


class CtfCategory(str, Enum):
    WEB = "web"
    API = "api"
    REVERSE = "reverse"
    PWN = "pwn"
    CRYPTO = "crypto"
    FORENSICS = "forensics"
    OSINT = "osint"
    MISC = "misc"


class CtfNetworkPolicy(str, Enum):
    DISABLED = "disabled"
    DECLARED_ENDPOINTS_ONLY = "declared_endpoints_only"


class ChallengeDefinition(BaseModel):
    model_config = ConfigDict(frozen=True)

    schema_version: str = "1"
    id: str
    title: str
    category: CtfCategory
    artifacts: tuple[str, ...] = Field(default_factory=tuple)
    authorized_endpoints: tuple[str, ...] = Field(default_factory=tuple)
    flag_pattern: str
    allow_ai: bool = False
    allow_automation: bool = False
    network_policy: CtfNetworkPolicy = CtfNetworkPolicy.DISABLED
    notes: str | None = None

    @field_validator("artifacts")
    @classmethod
    def reject_absolute_artifact_paths(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        for value in values:
            path = Path(value)
            if path.is_absolute() or ".." in path.parts:
                raise ValueError("CTF artifact paths must stay relative to the challenge file")
        return values


class CtfArtifactRecord(BaseModel):
    model_config = ConfigDict(frozen=True)

    path: str
    size_bytes: int
    sha256: str


class CtfIntakeResult(BaseModel):
    schema_version: str = "1"
    challenge_id: str
    autonomous_solving_allowed: bool
    network_execution_allowed: bool
    blockers: tuple[str, ...] = Field(default_factory=tuple)
    artifacts: tuple[CtfArtifactRecord, ...] = Field(default_factory=tuple)
    network_performed: bool = False


def inventory_challenge(challenge: ChallengeDefinition, base_dir: Path) -> CtfIntakeResult:
    blockers: list[str] = []
    if not challenge.allow_ai:
        blockers.append("challenge rules do not allow AI assistance")
    if not challenge.allow_automation:
        blockers.append("challenge rules do not allow automation")
    if (
        challenge.network_policy == CtfNetworkPolicy.DECLARED_ENDPOINTS_ONLY
        and not challenge.authorized_endpoints
    ):
        blockers.append("network policy requires at least one declared authorized endpoint")

    records: list[CtfArtifactRecord] = []
    for relative in challenge.artifacts:
        path = base_dir / relative
        if not path.is_file():
            blockers.append(f"declared artifact is missing: {relative}")
            continue
        data = path.read_bytes()
        records.append(
            CtfArtifactRecord(
                path=relative,
                size_bytes=len(data),
                sha256=hashlib.sha256(data).hexdigest(),
            )
        )

    return CtfIntakeResult(
        challenge_id=challenge.id,
        autonomous_solving_allowed=challenge.allow_ai and challenge.allow_automation,
        network_execution_allowed=(
            challenge.network_policy == CtfNetworkPolicy.DECLARED_ENDPOINTS_ONLY
            and bool(challenge.authorized_endpoints)
        ),
        blockers=tuple(blockers),
        artifacts=tuple(records),
    )
