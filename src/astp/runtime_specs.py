from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field


class RuntimeSpecKind(StrEnum):
    BROWSER = "browser"
    EXTERNAL_TOOL = "external_tool"


class RuntimeSpec(BaseModel):
    model_config = ConfigDict(frozen=True)

    id: str
    kind: RuntimeSpecKind
    image_or_distribution: str
    pinned_version: str
    capability_ids: tuple[str, ...]
    network_requires_permit: bool = True
    shell_allowed: bool = False
    signing_keys_available: bool = False
    max_output_bytes: int = Field(default=1_048_576, ge=1024, le=16_777_216)


def builtin_runtime_specs() -> tuple[RuntimeSpec, ...]:
    return (
        RuntimeSpec(
            id="playwright.isolated.v1",
            kind=RuntimeSpecKind.BROWSER,
            image_or_distribution="astp/playwright-worker",
            pinned_version="unbundled",
            capability_ids=("browser.observation.v1",),
        ),
        RuntimeSpec(
            id="security-tools.isolated.v1",
            kind=RuntimeSpecKind.EXTERNAL_TOOL,
            image_or_distribution="astp/security-tools-worker",
            pinned_version="unbundled",
            capability_ids=(
                "external.nmap.discovery.v1",
                "external.nuclei.safe.v1",
                "external.zap.baseline.v1",
            ),
        ),
    )
