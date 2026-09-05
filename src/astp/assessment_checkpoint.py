from __future__ import annotations

import hashlib
import json
import os
from datetime import UTC, datetime
from pathlib import Path

from pydantic import BaseModel, Field


class AssessmentCheckpoint(BaseModel):
    schema_version: str = "1"
    session_id: str
    engagement_id: str
    created_at: datetime
    completed_evidence_ids: list[str] = Field(default_factory=list)
    pending_evidence_ids: list[str] = Field(default_factory=list)
    policy_digest: str
    checkpoint_hash: str


def _canonical(payload: object) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str).encode()


def create_checkpoint(
    session_id: str,
    engagement_id: str,
    policy_digest: str,
    *,
    completed_evidence_ids: list[str] | None = None,
    pending_evidence_ids: list[str] | None = None,
) -> AssessmentCheckpoint:
    checkpoint = AssessmentCheckpoint(
        session_id=session_id,
        engagement_id=engagement_id,
        created_at=datetime.now(UTC),
        completed_evidence_ids=sorted(set(completed_evidence_ids or [])),
        pending_evidence_ids=sorted(set(pending_evidence_ids or [])),
        policy_digest=policy_digest,
        checkpoint_hash="pending",
    )
    payload = checkpoint.model_dump(mode="json", exclude={"checkpoint_hash"})
    digest = hashlib.sha256(_canonical(payload)).hexdigest()
    return checkpoint.model_copy(update={"checkpoint_hash": digest})


def verify_checkpoint(checkpoint: AssessmentCheckpoint) -> bool:
    payload = checkpoint.model_dump(mode="json", exclude={"checkpoint_hash"})
    return hashlib.sha256(_canonical(payload)).hexdigest() == checkpoint.checkpoint_hash


def write_checkpoint(path: Path, checkpoint: AssessmentCheckpoint) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    temporary.write_text(checkpoint.model_dump_json(indent=2) + "\n", encoding="utf-8")
    os.replace(temporary, path)
