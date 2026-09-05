from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field


class LoopDecision(StrEnum):
    CONTINUE = "continue"
    REPLAN = "replan"
    STOP = "stop"


class CoordinatorLoopInput(BaseModel):
    model_config = ConfigDict(frozen=True)

    accepted_evidence: int = 0
    new_signals: int = 0
    pending_verification: int = 0
    errors: int = 0
    error_budget: int = 1
    action_budget_remaining: int = 0
    policy_drift: bool = False
    attestation_fresh: bool = True


class CoordinatorLoopDecision(BaseModel):
    model_config = ConfigDict(frozen=True)

    decision: LoopDecision
    reason: str
    network_execution_authorized: bool = False
    requires_fresh_policy_evaluation: bool = True
    next_inputs: tuple[str, ...] = Field(default_factory=tuple)


def evaluate_coordinator_loop(value: CoordinatorLoopInput) -> CoordinatorLoopDecision:
    if value.policy_drift:
        return CoordinatorLoopDecision(decision=LoopDecision.STOP, reason="policy drift detected")
    if not value.attestation_fresh:
        return CoordinatorLoopDecision(
            decision=LoopDecision.STOP,
            reason="operational attestation is stale",
        )
    if value.errors >= value.error_budget:
        return CoordinatorLoopDecision(decision=LoopDecision.STOP, reason="error budget exhausted")
    if value.action_budget_remaining <= 0:
        return CoordinatorLoopDecision(decision=LoopDecision.STOP, reason="action budget exhausted")
    if value.new_signals > 0 or value.pending_verification > 0:
        return CoordinatorLoopDecision(
            decision=LoopDecision.REPLAN,
            reason="new evidence requires planning",
            next_inputs=("accepted_evidence", "signals", "verification_queue"),
        )
    return CoordinatorLoopDecision(
        decision=LoopDecision.CONTINUE,
        reason="no replanning trigger observed",
        next_inputs=("next_planned_action",),
    )
