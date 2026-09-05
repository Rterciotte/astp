from __future__ import annotations

import hashlib
from enum import StrEnum

from pydantic import BaseModel, ConfigDict

from astp.capability_action import CapabilityAction, CapabilityOperation
from astp.verifier_depth import VerifierSignal, VerifierSignalKind


class VerificationProposalStatus(StrEnum):
    READY_FOR_POLICY = "ready_for_policy"
    REVIEW_REQUIRED = "review_required"
    NO_ACTION = "no_action"


class VerificationActionProposal(BaseModel):
    model_config = ConfigDict(frozen=True)

    id: str
    verifier_id: str
    source_target: str
    status: VerificationProposalStatus
    action: CapabilityAction | None = None
    rationale: str
    requires_fresh_permit: bool = True
    state_changing: bool = False


def propose_verification_action(signal: VerifierSignal) -> VerificationActionProposal:
    action: CapabilityAction | None = None
    status = VerificationProposalStatus.NO_ACTION
    rationale = "Stored evidence is sufficient for this posture signal; no new request is proposed."

    if signal.kind is VerifierSignalKind.CORS_POLICY:
        action = CapabilityAction(
            capability_id="http.observation.v1",
            operation=CapabilityOperation.HTTP_GET,
            target=signal.target,
            metadata={"verification_profile": "cors-controlled-origin"},
        )
        status = VerificationProposalStatus.REVIEW_REQUIRED
        rationale = (
            "A controlled-origin comparison may be useful, but policy review is required first."
        )

    raw = f"{signal.verifier_id}|{signal.target}|{status.value}"
    digest = hashlib.sha256(raw.encode()).hexdigest()[:16]
    return VerificationActionProposal(
        id=f"verify-proposal-{digest}",
        verifier_id=signal.verifier_id,
        source_target=signal.target,
        status=status,
        action=action,
        rationale=rationale,
    )
