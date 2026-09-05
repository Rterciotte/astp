from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field

from astp.coordinator import CoordinatorStage


class StageExecutionBudget(BaseModel):
    model_config = ConfigDict(frozen=True)

    stage: CoordinatorStage
    max_network_actions: int = Field(default=10, ge=0, le=1000)
    max_errors: int = Field(default=3, ge=0, le=100)
    max_seconds: int = Field(default=300, ge=1, le=86_400)
    state_changing_actions_allowed: bool = False


class BudgetDecision(BaseModel):
    model_config = ConfigDict(frozen=True)

    allowed: bool
    reason: str


def evaluate_stage_budget(
    budget: StageExecutionBudget,
    *,
    network_actions: int,
    errors: int,
    elapsed_seconds: int,
    state_changing: bool = False,
) -> BudgetDecision:
    if state_changing and not budget.state_changing_actions_allowed:
        return BudgetDecision(
            allowed=False, reason="state-changing action exceeds this stage budget"
        )
    if network_actions >= budget.max_network_actions:
        return BudgetDecision(allowed=False, reason="network action budget exhausted")
    if errors >= budget.max_errors:
        return BudgetDecision(allowed=False, reason="error budget exhausted")
    if elapsed_seconds >= budget.max_seconds:
        return BudgetDecision(allowed=False, reason="stage time budget exhausted")
    return BudgetDecision(allowed=True, reason="stage budget allows another bounded action")
