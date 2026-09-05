from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from enum import StrEnum

from pydantic import BaseModel, Field

from astp.capability_action import CapabilityAction


class IntentStatus(StrEnum):
    PLANNED = "planned"
    REVIEW_REQUIRED = "review_required"
    AUTHORIZABLE = "authorizable"
    EXECUTED = "executed"
    BLOCKED = "blocked"


class ExecutionIntent(BaseModel):
    id: str
    engagement_id: str
    action: CapabilityAction
    status: IntentStatus = IntentStatus.PLANNED
    source_evidence_ids: list[str] = Field(default_factory=list)
    created_at: datetime
    requires_fresh_permit: bool = True


def build_execution_intent(
    engagement_id: str,
    action: CapabilityAction,
    *,
    source_evidence_ids: list[str] | None = None,
) -> ExecutionIntent:
    raw = json.dumps(
        [engagement_id, action.action_id(), sorted(source_evidence_ids or [])],
        separators=(",", ":"),
    ).encode()
    return ExecutionIntent(
        id="intent-" + hashlib.sha256(raw).hexdigest()[:16],
        engagement_id=engagement_id,
        action=action,
        source_evidence_ids=sorted(source_evidence_ids or []),
        created_at=datetime.now(UTC),
    )
