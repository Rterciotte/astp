from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel, ConfigDict

from astp.coordinator import CoordinatorStage


class StageGateDecision(StrEnum):
    ALLOW = "allow"
    BLOCK = "block"


class CoordinatorGateContext(BaseModel):
    model_config = ConfigDict(frozen=True)

    evidence_available: bool = False
    verification_queue_empty: bool = True
    unresolved_retests: bool = False
    report_ready: bool = False
    review_approved: bool = False


class CoordinatorGateResult(BaseModel):
    model_config = ConfigDict(frozen=True)

    from_stage: CoordinatorStage
    to_stage: CoordinatorStage
    decision: StageGateDecision
    reason: str


_STAGE_ORDER = tuple(CoordinatorStage)


def evaluate_stage_transition(
    from_stage: CoordinatorStage,
    to_stage: CoordinatorStage,
    context: CoordinatorGateContext,
) -> CoordinatorGateResult:
    current = _STAGE_ORDER.index(from_stage)
    requested = _STAGE_ORDER.index(to_stage)
    if requested != current + 1:
        return CoordinatorGateResult(
            from_stage=from_stage,
            to_stage=to_stage,
            decision=StageGateDecision.BLOCK,
            reason="coordinator transitions must advance exactly one stage",
        )
    if to_stage is CoordinatorStage.VERIFICATION and not context.evidence_available:
        return CoordinatorGateResult(
            from_stage=from_stage,
            to_stage=to_stage,
            decision=StageGateDecision.BLOCK,
            reason="verification requires evidence from the observation stage",
        )
    if to_stage is CoordinatorStage.RETEST and not context.verification_queue_empty:
        return CoordinatorGateResult(
            from_stage=from_stage,
            to_stage=to_stage,
            decision=StageGateDecision.BLOCK,
            reason="retest cannot start while verification work remains unresolved",
        )
    if to_stage is CoordinatorStage.REPORT and context.unresolved_retests:
        return CoordinatorGateResult(
            from_stage=from_stage,
            to_stage=to_stage,
            decision=StageGateDecision.BLOCK,
            reason="report stage requires all scheduled retests to reach a terminal state",
        )
    if to_stage is CoordinatorStage.REVIEW and not context.report_ready:
        return CoordinatorGateResult(
            from_stage=from_stage,
            to_stage=to_stage,
            decision=StageGateDecision.BLOCK,
            reason="operator review requires a finalized report candidate",
        )
    if to_stage is CoordinatorStage.CLOSURE and not context.review_approved:
        return CoordinatorGateResult(
            from_stage=from_stage,
            to_stage=to_stage,
            decision=StageGateDecision.BLOCK,
            reason="closure requires an approved operator review",
        )
    return CoordinatorGateResult(
        from_stage=from_stage,
        to_stage=to_stage,
        decision=StageGateDecision.ALLOW,
        reason="stage prerequisites are satisfied",
    )
