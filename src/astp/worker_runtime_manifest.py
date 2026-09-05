from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field


class RuntimeKind(StrEnum):
    BROWSER = "browser"
    EXTERNAL_TOOL = "external_tool"


class WorkerRuntimeManifest(BaseModel):
    model_config = ConfigDict(frozen=True)

    id: str
    kind: RuntimeKind
    capability_ids: tuple[str, ...]
    bundled: bool = False
    field_tested: bool = False
    permit_consumed_before_io: bool = True
    signing_keys_available: bool = False
    arbitrary_shell_allowed: bool = False
    blockers: tuple[str, ...] = Field(default_factory=tuple)

    @property
    def operational_ready(self) -> bool:
        return self.bundled and self.field_tested and self.permit_consumed_before_io


def builtin_worker_runtime_manifests() -> tuple[WorkerRuntimeManifest, ...]:
    return (
        WorkerRuntimeManifest(
            id="playwright.isolated.v1",
            kind=RuntimeKind.BROWSER,
            capability_ids=("browser.observation.v1",),
            blockers=("isolated Playwright image/runtime has not been bundled and field-tested",),
        ),
        WorkerRuntimeManifest(
            id="security-tools.isolated.v1",
            kind=RuntimeKind.EXTERNAL_TOOL,
            capability_ids=(
                "external.nmap.discovery.v1",
                "external.nuclei.safe.v1",
                "external.zap.baseline.v1",
            ),
            blockers=("version-pinned tool image/runtime has not been bundled and field-tested",),
        ),
    )
