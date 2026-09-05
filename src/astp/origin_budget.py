from __future__ import annotations

from collections import Counter
from urllib.parse import urlsplit

from pydantic import BaseModel, Field


class OriginBudget(BaseModel):
    max_actions_per_origin: int = Field(default=10, ge=1, le=1000)


class OriginBudgetState(BaseModel):
    counts: dict[str, int] = Field(default_factory=dict)


def canonical_origin(target: str) -> str:
    parsed = urlsplit(target)
    if not parsed.scheme or not parsed.hostname:
        raise ValueError("target must be an absolute URL")
    port = parsed.port
    default_port = 443 if parsed.scheme.lower() == "https" else 80
    suffix = "" if port is None or port == default_port else f":{port}"
    return f"{parsed.scheme.lower()}://{parsed.hostname.lower()}{suffix}"


def check_and_record_origin(
    budget: OriginBudget,
    state: OriginBudgetState,
    target: str,
) -> OriginBudgetState:
    origin = canonical_origin(target)
    counts = Counter(state.counts)
    if counts[origin] >= budget.max_actions_per_origin:
        raise ValueError(f"origin action budget exhausted for {origin}")
    counts[origin] += 1
    return OriginBudgetState(counts=dict(counts))
