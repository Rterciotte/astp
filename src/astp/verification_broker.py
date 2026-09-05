from __future__ import annotations

from pydantic import BaseModel

from astp.verification_queue import VerificationQueueItem
from astp.verification_review import (
    VerificationReview,
    VerificationReviewDecision,
    verification_item_hash,
)


class VerificationAuthorizationCandidate(BaseModel):
    schema_version: str = "1"
    queue_item_id: str
    finding_id: str
    finding_key: str
    review_hash: str
    requires_policy_authorization: bool = True
    requires_fresh_permit: bool = True
    execution_performed: bool = False


def broker_reviewed_verification(
    item: VerificationQueueItem,
    review: VerificationReview,
) -> VerificationAuthorizationCandidate:
    if review.queue_item_id != item.id or review.queue_item_hash != verification_item_hash(item):
        raise ValueError("verification review is not bound to the current queue item")
    if review.decision != VerificationReviewDecision.APPROVE_FOR_AUTHORIZATION:
        raise ValueError("verification item is not approved for authorization")
    return VerificationAuthorizationCandidate(
        queue_item_id=item.id,
        finding_id=item.finding_id,
        finding_key=item.plan.finding_key,
        review_hash=review.queue_item_hash,
    )
