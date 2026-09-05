from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime

from pydantic import BaseModel, ConfigDict, Field

from astp.coordinator import CoordinatorStage


class RecoveryCheckpoint(BaseModel):
    model_config = ConfigDict(frozen=True)

    id: str
    engagement_id: str
    stage: CoordinatorStage
    policy_digest: str
    accepted_evidence_ids: tuple[str, ...] = Field(default_factory=tuple)
    pending_action_ids: tuple[str, ...] = Field(default_factory=tuple)
    created_at: datetime
    checkpoint_hash: str


def build_recovery_checkpoint(
    engagement_id: str,
    stage: CoordinatorStage,
    policy_digest: str,
    *,
    accepted_evidence_ids: tuple[str, ...] = (),
    pending_action_ids: tuple[str, ...] = (),
    now: datetime | None = None,
) -> RecoveryCheckpoint:
    created_at = now or datetime.now(UTC)
    payload = {
        "engagement_id": engagement_id,
        "stage": stage.value,
        "policy_digest": policy_digest,
        "accepted_evidence_ids": list(accepted_evidence_ids),
        "pending_action_ids": list(pending_action_ids),
        "created_at": created_at.isoformat(),
    }
    digest = hashlib.sha256(json.dumps(payload, sort_keys=True).encode()).hexdigest()
    return RecoveryCheckpoint(
        id=f"checkpoint-{digest[:16]}",
        engagement_id=engagement_id,
        stage=stage,
        policy_digest=policy_digest,
        accepted_evidence_ids=accepted_evidence_ids,
        pending_action_ids=pending_action_ids,
        created_at=created_at,
        checkpoint_hash=digest,
    )
