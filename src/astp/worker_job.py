from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from enum import Enum

from pydantic import BaseModel, Field


class WorkerJobStatus(str, Enum):
    PREPARED = "prepared"
    DISPATCHED = "dispatched"
    COMPLETED = "completed"
    FAILED = "failed"


class WorkerJobEnvelope(BaseModel):
    schema_version: str = "1"
    id: str
    capability_id: str
    target: str
    action_id: str
    permit_id: str
    evidence_destination: str
    prepared_at: datetime
    allowed_environment_keys: list[str] = Field(default_factory=list)
    signing_keys_included: bool = False
    arbitrary_mounts_allowed: bool = False
    arbitrary_network_allowed: bool = False


def prepare_worker_job(
    capability_id: str,
    target: str,
    action_id: str,
    permit_id: str,
    evidence_destination: str,
) -> WorkerJobEnvelope:
    raw = json.dumps(
        [capability_id, target, action_id, permit_id],
        separators=(",", ":"),
    ).encode()
    job_id = "worker-job-" + hashlib.sha256(raw).hexdigest()[:16]
    return WorkerJobEnvelope(
        id=job_id,
        capability_id=capability_id,
        target=target,
        action_id=action_id,
        permit_id=permit_id,
        evidence_destination=evidence_destination,
        prepared_at=datetime.now(UTC),
    )
