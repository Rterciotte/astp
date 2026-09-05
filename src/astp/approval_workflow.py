from __future__ import annotations

import hashlib
from datetime import UTC, datetime
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, field_validator


class ApprovalDecision(StrEnum):
    APPROVE = "approve"
    REJECT = "reject"


class HighRiskActionApproval(BaseModel):
    model_config = ConfigDict(frozen=True)

    id: str
    action_id: str
    operator: str
    decision: ApprovalDecision
    approved_at: datetime
    autonomous_execution_allowed: bool = False
    exact_action_binding: bool = True

    @field_validator("approved_at")
    @classmethod
    def timezone_required(cls, value: datetime) -> datetime:
        if value.tzinfo is None:
            raise ValueError("approval timestamp must be timezone-aware")
        return value


def record_high_risk_approval(
    action_id: str,
    operator: str,
    decision: ApprovalDecision,
    *,
    now: datetime | None = None,
) -> HighRiskActionApproval:
    timestamp = now or datetime.now(UTC)
    raw = f"{action_id}|{operator}|{timestamp.isoformat()}".encode()
    digest = hashlib.sha256(raw).hexdigest()[:16]
    return HighRiskActionApproval(
        id=f"approval-{digest}",
        action_id=action_id,
        operator=operator,
        decision=decision,
        approved_at=timestamp,
    )
