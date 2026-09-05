from __future__ import annotations

import hashlib

from pydantic import BaseModel, ConfigDict

from astp.capability_action import CapabilityAction
from astp.verification_broker import VerificationAuthorizationCandidate


class VerificationExecutionEnvelope(BaseModel):
    model_config = ConfigDict(frozen=True)

    id: str
    queue_item_id: str
    finding_id: str
    action: CapabilityAction
    requires_policy_authorization: bool = True
    requires_fresh_permit: bool = True
    requires_capability_grant: bool = True
    execution_performed: bool = False


def prepare_verification_execution(
    candidate: VerificationAuthorizationCandidate,
    action: CapabilityAction,
) -> VerificationExecutionEnvelope:
    digest = hashlib.sha256(
        f"{candidate.queue_item_id}|{candidate.review_hash}|{action.action_id()}".encode()
    ).hexdigest()[:16]
    return VerificationExecutionEnvelope(
        id=f"verification-exec-{digest}",
        queue_item_id=candidate.queue_item_id,
        finding_id=candidate.finding_id,
        action=action,
    )
