from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from enum import Enum

from pydantic import BaseModel, Field

from astp.verification_queue import VerificationQueueItem


class VerificationReviewDecision(str, Enum):
    APPROVE_FOR_AUTHORIZATION = "approve_for_authorization"
    REJECT = "reject"
    NEEDS_CHANGES = "needs_changes"


class VerificationReview(BaseModel):
    schema_version: str = "1"
    queue_item_id: str
    queue_item_hash: str
    reviewer: str
    decision: VerificationReviewDecision
    reviewed_at: datetime
    notes: list[str] = Field(default_factory=list)


def verification_item_hash(item: VerificationQueueItem) -> str:
    payload = item.model_dump(mode="json")
    raw = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(raw).hexdigest()


def review_verification_item(
    item: VerificationQueueItem,
    reviewer: str,
    decision: VerificationReviewDecision,
    *,
    notes: list[str] | None = None,
) -> VerificationReview:
    if not reviewer.strip():
        raise ValueError("reviewer is required")
    return VerificationReview(
        queue_item_id=item.id,
        queue_item_hash=verification_item_hash(item),
        reviewer=reviewer.strip(),
        decision=decision,
        reviewed_at=datetime.now(UTC),
        notes=notes or [],
    )
