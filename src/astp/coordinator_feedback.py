from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field


class ReplanDecision(StrEnum):
    CONTINUE = "continue"
    REPLAN = "replan"
    STOP = "stop"


class CoordinatorFeedback(BaseModel):
    model_config = ConfigDict(frozen=True)

    accepted_evidence: int = 0
    rejected_evidence: int = 0
    new_signals: int = 0
    new_verification_proposals: int = 0
    errors: int = 0
    decision: ReplanDecision
    reasons: tuple[str, ...] = Field(default_factory=tuple)


def evaluate_feedback(
    *,
    accepted_evidence: int,
    rejected_evidence: int,
    new_signals: int,
    new_verification_proposals: int,
    errors: int,
    error_budget: int = 3,
) -> CoordinatorFeedback:
    reasons: list[str] = []
    if errors >= error_budget:
        decision = ReplanDecision.STOP
        reasons.append("failure circuit reached the configured error budget")
    elif rejected_evidence > 0:
        decision = ReplanDecision.REPLAN
        reasons.append("rejected evidence requires provenance or policy recovery")
    elif new_verification_proposals > 0 or new_signals > 0:
        decision = ReplanDecision.REPLAN
        reasons.append("new evidence-derived work is available")
    else:
        decision = ReplanDecision.CONTINUE
        reasons.append("no new work or stop condition was observed")
    return CoordinatorFeedback(
        accepted_evidence=accepted_evidence,
        rejected_evidence=rejected_evidence,
        new_signals=new_signals,
        new_verification_proposals=new_verification_proposals,
        errors=errors,
        decision=decision,
        reasons=tuple(reasons),
    )
