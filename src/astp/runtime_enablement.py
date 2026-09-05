from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field


class RuntimeEnablement(BaseModel):
    model_config = ConfigDict(frozen=True)

    runtime_id: str
    bundled: bool
    executable_bridge: bool
    permit_consumed_before_io: bool
    field_qualified: bool = False
    supported_operations: tuple[str, ...] = Field(default_factory=tuple)

    @property
    def operational_ready(self) -> bool:
        return (
            self.bundled
            and self.executable_bridge
            and self.permit_consumed_before_io
            and self.field_qualified
        )


def candidate_runtime_enablement() -> tuple[RuntimeEnablement, ...]:
    return (
        RuntimeEnablement(
            runtime_id="playwright.isolated.v1",
            bundled=True,
            executable_bridge=True,
            permit_consumed_before_io=True,
            field_qualified=False,
            supported_operations=(
                "browser.navigate",
                "browser.dom_snapshot",
                "browser.screenshot",
            ),
        ),
        RuntimeEnablement(
            runtime_id="security-tools.isolated.v1",
            bundled=True,
            executable_bridge=True,
            permit_consumed_before_io=True,
            field_qualified=False,
            supported_operations=(
                "external.nmap.discovery",
                "external.nuclei.safe",
                "external.zap.baseline",
            ),
        ),
    )
