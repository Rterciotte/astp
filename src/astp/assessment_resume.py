from __future__ import annotations

from pydantic import BaseModel, Field

from astp.assessment_checkpoint import AssessmentCheckpoint, verify_checkpoint


class AssessmentResumeDecision(BaseModel):
    allowed: bool
    reasons: list[str] = Field(default_factory=list)
    requires_replan: bool = False


def evaluate_assessment_resume(
    checkpoint: AssessmentCheckpoint,
    *,
    engagement_id: str,
    current_policy_digest: str,
) -> AssessmentResumeDecision:
    reasons: list[str] = []
    if not verify_checkpoint(checkpoint):
        return AssessmentResumeDecision(allowed=False, reasons=["checkpoint integrity failed"])
    if checkpoint.engagement_id != engagement_id:
        reasons.append("checkpoint belongs to a different engagement")
    if checkpoint.policy_digest != current_policy_digest:
        reasons.append("policy digest changed")
        return AssessmentResumeDecision(allowed=False, reasons=reasons, requires_replan=True)
    return AssessmentResumeDecision(allowed=not reasons, reasons=reasons)
