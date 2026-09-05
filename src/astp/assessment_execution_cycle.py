from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field


class CycleDecision(StrEnum):
    CONTINUE = "continue"
    REPLAN = "replan"
    STOP = "stop"
    COMPLETE = "complete"


class AssessmentCycleInput(BaseModel):
    model_config = ConfigDict(frozen=True)

    accepted_evidence: int = 0
    rejected_evidence: int = 0
    new_signals: int = 0
    pending_verification: int = 0
    pending_retests: int = 0
    report_ready: bool = False
    review_approved: bool = False
    policy_drift: bool = False
    attestation_fresh: bool = True
    action_budget_remaining: int = 1
    error_budget_remaining: int = 1


class AssessmentCycleDecision(BaseModel):
    model_config = ConfigDict(frozen=True)

    decision: CycleDecision
    requires_fresh_policy_evaluation: bool = True
    network_execution_authorized: bool = False
    reasons: tuple[str, ...] = Field(default_factory=tuple)


def evaluate_assessment_cycle(value: AssessmentCycleInput) -> AssessmentCycleDecision:
    if value.policy_drift:
        return AssessmentCycleDecision(
            decision=CycleDecision.STOP, reasons=("policy drift detected",)
        )
    if not value.attestation_fresh:
        return AssessmentCycleDecision(
            decision=CycleDecision.STOP,
            reasons=("operational attestation is stale",),
        )
    if value.action_budget_remaining <= 0:
        return AssessmentCycleDecision(
            decision=CycleDecision.STOP, reasons=("action budget exhausted",)
        )
    if value.error_budget_remaining <= 0:
        return AssessmentCycleDecision(
            decision=CycleDecision.STOP, reasons=("error budget exhausted",)
        )
    if value.rejected_evidence or value.new_signals or value.pending_verification:
        return AssessmentCycleDecision(decision=CycleDecision.REPLAN)
    if value.pending_retests:
        return AssessmentCycleDecision(decision=CycleDecision.CONTINUE)
    if value.report_ready and value.review_approved:
        return AssessmentCycleDecision(decision=CycleDecision.COMPLETE)
    return AssessmentCycleDecision(decision=CycleDecision.CONTINUE)
