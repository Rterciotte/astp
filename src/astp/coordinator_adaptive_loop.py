from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field


class AdaptiveLoopDecision(StrEnum):
    CONTINUE = "continue"
    REPLAN = "replan"
    STOP = "stop"


class AdaptiveLoopInput(BaseModel):
    model_config = ConfigDict(frozen=True)

    accepted_evidence: int = 0
    rejected_evidence: int = 0
    new_hypotheses: int = 0
    pending_verifications: int = 0
    consumed_actions: int = 0
    max_actions: int = Field(default=20, ge=1)
    errors: int = 0
    max_errors: int = Field(default=3, ge=1)


class AdaptiveLoopResult(BaseModel):
    model_config = ConfigDict(frozen=True)

    decision: AdaptiveLoopDecision
    reasons: tuple[str, ...] = Field(default_factory=tuple)
    network_execution_authorized: bool = False


def evaluate_adaptive_loop(state: AdaptiveLoopInput) -> AdaptiveLoopResult:
    reasons: list[str] = []
    if state.errors >= state.max_errors:
        reasons.append("error budget exhausted")
        decision = AdaptiveLoopDecision.STOP
    elif state.consumed_actions >= state.max_actions:
        reasons.append("action budget exhausted")
        decision = AdaptiveLoopDecision.STOP
    elif state.rejected_evidence:
        reasons.append("rejected evidence requires recovery or policy re-evaluation")
        decision = AdaptiveLoopDecision.REPLAN
    elif state.new_hypotheses or state.pending_verifications:
        reasons.append("new evidence-derived work requires replanning")
        decision = AdaptiveLoopDecision.REPLAN
    else:
        reasons.append("no new work was produced")
        decision = AdaptiveLoopDecision.CONTINUE
    return AdaptiveLoopResult(decision=decision, reasons=tuple(reasons))
