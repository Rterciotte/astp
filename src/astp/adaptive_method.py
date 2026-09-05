from __future__ import annotations

from enum import Enum

from pydantic import BaseModel

from astp.observation import HttpObservationEvidence


class EscalationReason(str, Enum):
    BODY_ALREADY_CAPTURED = "body_already_captured"
    BODY_NEEDED = "body_needed"
    METADATA_SUFFICIENT = "metadata_sufficient"


class AdaptiveMethodDecision(BaseModel):
    method: str | None
    requires_new_permit: bool
    reason: EscalationReason


def choose_followup_method(
    evidence: HttpObservationEvidence, *, body_evidence_required: bool
) -> AdaptiveMethodDecision:
    if evidence.method.upper() != "HEAD":
        return AdaptiveMethodDecision(
            method=None, requires_new_permit=False, reason=EscalationReason.BODY_ALREADY_CAPTURED
        )
    if body_evidence_required and evidence.status_code not in {204, 304}:
        return AdaptiveMethodDecision(
            method="GET", requires_new_permit=True, reason=EscalationReason.BODY_NEEDED
        )
    return AdaptiveMethodDecision(
        method=None, requires_new_permit=False, reason=EscalationReason.METADATA_SUFFICIENT
    )
