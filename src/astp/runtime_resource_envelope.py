from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field


class RuntimeResourceEnvelope(BaseModel):
    model_config = ConfigDict(frozen=True)

    cpus: float = Field(gt=0, le=2)
    memory_mb: int = Field(ge=128, le=1536)
    pids_limit: int = Field(ge=32, le=512)

    def docker_argv(self) -> tuple[str, ...]:
        return (
            "--cpus",
            f"{self.cpus:g}",
            "--memory",
            f"{self.memory_mb}m",
            "--pids-limit",
            str(self.pids_limit),
        )


def default_resource_envelopes() -> dict[str, RuntimeResourceEnvelope]:
    """Conservative serial-execution limits for a small Docker Desktop VM."""
    return {
        "playwright.isolated.v1": RuntimeResourceEnvelope(cpus=1.0, memory_mb=768, pids_limit=192),
        "security-tools.isolated.v1": RuntimeResourceEnvelope(
            cpus=0.5, memory_mb=256, pids_limit=96
        ),
        "zap.isolated.v1": RuntimeResourceEnvelope(cpus=1.0, memory_mb=1024, pids_limit=256),
    }
