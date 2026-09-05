from __future__ import annotations

import hashlib

from pydantic import BaseModel, ConfigDict, Field

from astp.coordinator import CoordinatorStage
from astp.execution_budget import BudgetDecision, StageExecutionBudget, evaluate_stage_budget


class CoordinatorExecutionTicket(BaseModel):
    model_config = ConfigDict(frozen=True)

    id: str
    engagement_id: str
    stage: CoordinatorStage
    action_ids: tuple[str, ...] = Field(default_factory=tuple)
    fresh_permit_per_action: bool = True
    execution_enabled: bool = False
    state_changing_allowed: bool = False


def build_execution_ticket(
    engagement_id: str,
    stage: CoordinatorStage,
    action_ids: tuple[str, ...],
) -> CoordinatorExecutionTicket:
    unique = tuple(dict.fromkeys(action_ids))
    raw = f"{engagement_id}|{stage.value}|{'|'.join(unique)}"
    digest = hashlib.sha256(raw.encode()).hexdigest()[:16]
    return CoordinatorExecutionTicket(
        id=f"coord-ticket-{digest}",
        engagement_id=engagement_id,
        stage=stage,
        action_ids=unique,
    )


def evaluate_ticket_budget(
    ticket: CoordinatorExecutionTicket,
    budget: StageExecutionBudget,
    *,
    network_actions: int,
    errors: int,
    elapsed_seconds: int,
) -> BudgetDecision:
    if ticket.stage is not budget.stage:
        return BudgetDecision(
            allowed=False, reason="ticket and budget are bound to different stages"
        )
    return evaluate_stage_budget(
        budget,
        network_actions=network_actions,
        errors=errors,
        elapsed_seconds=elapsed_seconds,
        state_changing=ticket.state_changing_allowed,
    )
