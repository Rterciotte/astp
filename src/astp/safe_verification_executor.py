from __future__ import annotations

from collections.abc import Callable
from enum import StrEnum

from pydantic import BaseModel, ConfigDict

from astp.capability_action import CapabilityAction, CapabilityOperation
from astp.capability_grant import SignedCapabilityGrant
from astp.permits import SignedExecutionPermit
from astp.verification_execution import VerificationExecutionEnvelope


class VerificationExecutionStatus(StrEnum):
    COMPLETED = "completed"
    REJECTED = "rejected"


class SafeVerificationResult(BaseModel):
    model_config = ConfigDict(frozen=True)

    envelope_id: str
    action_id: str
    status: VerificationExecutionStatus
    evidence_id: str | None = None
    reason: str


VerificationDispatcher = Callable[
    [SignedCapabilityGrant, SignedExecutionPermit, CapabilityAction], str
]

_SAFE_OPERATIONS = {
    CapabilityOperation.HTTP_GET,
    CapabilityOperation.HTTP_HEAD,
    CapabilityOperation.DNS_A,
    CapabilityOperation.DNS_AAAA,
    CapabilityOperation.DNS_CNAME,
    CapabilityOperation.TLS_HANDSHAKE,
}


def execute_safe_verification(
    envelope: VerificationExecutionEnvelope,
    grant: SignedCapabilityGrant,
    permit: SignedExecutionPermit,
    dispatcher: VerificationDispatcher,
) -> SafeVerificationResult:
    if envelope.action.operation not in _SAFE_OPERATIONS:
        return SafeVerificationResult(
            envelope_id=envelope.id,
            action_id=envelope.action.action_id(),
            status=VerificationExecutionStatus.REJECTED,
            reason="verification action is outside the safe autonomous operation set",
        )
    if grant.payload.permit_id != permit.payload.permit_id:
        return SafeVerificationResult(
            envelope_id=envelope.id,
            action_id=envelope.action.action_id(),
            status=VerificationExecutionStatus.REJECTED,
            reason="capability grant and execution permit are not bound together",
        )
    evidence_id = dispatcher(grant, permit, envelope.action)
    return SafeVerificationResult(
        envelope_id=envelope.id,
        action_id=envelope.action.action_id(),
        status=VerificationExecutionStatus.COMPLETED,
        evidence_id=evidence_id,
        reason="safe verification executed through the permit-gated dispatcher",
    )
