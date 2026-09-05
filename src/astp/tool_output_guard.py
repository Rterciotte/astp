from __future__ import annotations

from pydantic import BaseModel, ConfigDict


class ToolOutputGuardResult(BaseModel):
    model_config = ConfigDict(frozen=True)
    accepted: bool
    truncated: bool
    original_bytes: int
    stored_bytes: int


def bound_tool_output(
    data: bytes, max_bytes: int = 1_048_576
) -> tuple[bytes, ToolOutputGuardResult]:
    if max_bytes <= 0:
        raise ValueError("max_bytes must be positive")
    bounded = data[:max_bytes]
    return bounded, ToolOutputGuardResult(
        accepted=True,
        truncated=len(data) > max_bytes,
        original_bytes=len(data),
        stored_bytes=len(bounded),
    )
