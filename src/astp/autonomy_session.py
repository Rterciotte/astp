from __future__ import annotations

from datetime import UTC, datetime

from pydantic import BaseModel, Field

from astp.session_budget import BudgetDecision, SessionBudget, SessionCounters, evaluate_budget
from astp.work_queue import WorkQueue


class SessionPreparedItem(BaseModel):
    queue_id: str
    target: str
    engagement_id: str
    test_id: str
    requires_fresh_permit: bool = True
    network_execution_performed: bool = False


class AutonomySessionPlan(BaseModel):
    schema_version: str = "1"
    created_at: datetime
    budget: SessionBudget
    budget_decision: BudgetDecision
    items: list[SessionPreparedItem] = Field(default_factory=list)
    execution_enabled: bool = False


def prepare_autonomy_session(
    queue: WorkQueue,
    budget: SessionBudget,
    *,
    counters: SessionCounters | None = None,
    now: datetime | None = None,
) -> AutonomySessionPlan:
    current = now or datetime.now(UTC)
    current_counters = counters or SessionCounters(started_at=current)
    decision = evaluate_budget(budget, current_counters, now=current)
    items: list[SessionPreparedItem] = []
    if decision.allowed:
        remaining = max(0, budget.max_actions - current_counters.actions)
        for item in queue.items[:remaining]:
            items.append(
                SessionPreparedItem(
                    queue_id=item.queue_id,
                    target=item.target,
                    engagement_id=item.engagement_id,
                    test_id=item.test_id,
                )
            )
    return AutonomySessionPlan(
        created_at=current,
        budget=budget,
        budget_decision=decision,
        items=items,
        execution_enabled=False,
    )
