from __future__ import annotations

import shutil

from pydantic import BaseModel, ConfigDict


class RuntimeProbeResult(BaseModel):
    model_config = ConfigDict(frozen=True)

    runtime_id: str
    executable: str
    installed: bool
    executable_path: str | None
    network_execution_performed: bool = False
    operational_ready: bool = False


def probe_runtime_executable(runtime_id: str, executable: str) -> RuntimeProbeResult:
    path = shutil.which(executable)
    return RuntimeProbeResult(
        runtime_id=runtime_id,
        executable=executable,
        installed=path is not None,
        executable_path=path,
        operational_ready=False,
    )


def builtin_runtime_probes() -> tuple[RuntimeProbeResult, ...]:
    return (
        probe_runtime_executable("playwright.isolated.v1", "playwright"),
        probe_runtime_executable("nmap.safe-discovery.v1", "nmap"),
        probe_runtime_executable("nuclei.safe-templates.v1", "nuclei"),
        probe_runtime_executable("zap.baseline.v1", "zap-baseline"),
    )
