from __future__ import annotations

from datetime import UTC, datetime, timedelta
from enum import Enum

from pydantic import BaseModel, Field


class StopReason(str, Enum):
    ACTION_BUDGET = "action_budget"
    REQUEST_BUDGET = "request_budget"
    ERROR_BUDGET = "error_budget"
    WALL_CLOCK = "wall_clock"
    DEPTH_BUDGET = "depth_budget"


class SessionBudget(BaseModel):
    max_actions: int = Field(default=20, ge=1, le=10000)
    max_requests: int = Field(default=20, ge=1, le=10000)
    max_errors: int = Field(default=3, ge=0, le=1000)
    max_wall_clock_seconds: int = Field(default=900, ge=1, le=86400)
    max_discovery_depth: int = Field(default=3, ge=0, le=50)


class SessionCounters(BaseModel):
    started_at: datetime
    actions: int = 0
    requests: int = 0
    errors: int = 0
    depth: int = 0


class BudgetDecision(BaseModel):
    allowed: bool
    reasons: list[StopReason] = Field(default_factory=list)


def evaluate_budget(
    budget: SessionBudget,
    counters: SessionCounters,
    *,
    now: datetime | None = None,
) -> BudgetDecision:
    current = now or datetime.now(UTC)
    reasons: list[StopReason] = []
    if counters.actions >= budget.max_actions:
        reasons.append(StopReason.ACTION_BUDGET)
    if counters.requests >= budget.max_requests:
        reasons.append(StopReason.REQUEST_BUDGET)
    if counters.errors >= budget.max_errors and budget.max_errors >= 0:
        reasons.append(StopReason.ERROR_BUDGET)
    if current >= counters.started_at + timedelta(seconds=budget.max_wall_clock_seconds):
        reasons.append(StopReason.WALL_CLOCK)
    if counters.depth > budget.max_discovery_depth:
        reasons.append(StopReason.DEPTH_BUDGET)
    return BudgetDecision(allowed=not reasons, reasons=reasons)
