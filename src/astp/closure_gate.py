from __future__ import annotations

from pydantic import BaseModel, Field

from astp.operator_review import OperatorReview, ReviewDecision
from astp.report_finalization import ReportFinalization


class AssessmentClosureDecision(BaseModel):
    closable: bool
    reasons: list[str] = Field(default_factory=list)


def evaluate_closure(
    review: OperatorReview,
    finalization: ReportFinalization,
    *,
    unresolved_verifications: int,
    quarantined_evidence: int,
) -> AssessmentClosureDecision:
    reasons: list[str] = []
    if review.decision != ReviewDecision.APPROVE:
        reasons.append("assessment is not approved")
    if not finalization.publishable:
        reasons.append("report is not publishable")
    if unresolved_verifications:
        reasons.append(f"{unresolved_verifications} verification items remain unresolved")
    if quarantined_evidence:
        reasons.append(f"{quarantined_evidence} evidence items remain quarantined")
    return AssessmentClosureDecision(closable=not reasons, reasons=reasons)
