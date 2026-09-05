from __future__ import annotations

import hashlib
import json
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field, field_validator


class RuntimeFamily(StrEnum):
    PLAYWRIGHT = "playwright"
    SECURITY_TOOLS = "security-tools"
    ZAP = "zap"


class RuntimeBuildManifest(BaseModel):
    model_config = ConfigDict(frozen=True)
    runtime_id: str
    family: RuntimeFamily
    dockerfile: str
    context_dir: str
    image_repository: str
    expected_executable: str
    build_args: tuple[str, ...] = Field(default_factory=tuple)

    @field_validator(
        "runtime_id", "dockerfile", "context_dir", "image_repository", "expected_executable"
    )
    @classmethod
    def nonempty(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("runtime build fields cannot be blank")
        return value

    def manifest_hash(self) -> str:
        raw = json.dumps(self.model_dump(mode="json"), sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(raw.encode()).hexdigest()


def default_runtime_builds() -> tuple[RuntimeBuildManifest, ...]:
    return (
        RuntimeBuildManifest(
            runtime_id="playwright.isolated.v1",
            family=RuntimeFamily.PLAYWRIGHT,
            dockerfile="workers/playwright/Dockerfile",
            context_dir=".",
            image_repository="astp/playwright-worker",
            expected_executable="python",
        ),
        RuntimeBuildManifest(
            runtime_id="security-tools.isolated.v1",
            family=RuntimeFamily.SECURITY_TOOLS,
            dockerfile="workers/security-tools/Dockerfile",
            context_dir=".",
            image_repository="astp/security-tools-worker",
            expected_executable="python",
        ),
        RuntimeBuildManifest(
            runtime_id="zap.isolated.v1",
            family=RuntimeFamily.ZAP,
            dockerfile="workers/zap/Dockerfile",
            context_dir=".",
            image_repository="astp/zap-worker",
            expected_executable="python",
        ),
    )
