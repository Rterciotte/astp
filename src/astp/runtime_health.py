from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field


class RuntimeHealthReport(BaseModel):
    model_config = ConfigDict(frozen=True)

    runtime_id: str
    artifact_digest: str
    version: str
    healthy: bool
    capabilities: tuple[str, ...] = Field(default_factory=tuple)
    network_test_performed: bool = False
    signing_keys_visible: bool = False
    shell_available: bool = False


def evaluate_health(report: RuntimeHealthReport) -> tuple[str, ...]:
    blockers: list[str] = []
    if not report.healthy:
        blockers.append("runtime health probe failed")
    if report.network_test_performed:
        blockers.append("health probe must not perform target network I/O")
    if report.signing_keys_visible:
        blockers.append("runtime can see signing keys")
    if report.shell_available:
        blockers.append("runtime exposes an interactive shell")
    return tuple(blockers)
