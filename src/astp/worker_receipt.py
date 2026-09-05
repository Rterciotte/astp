from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime

from pydantic import BaseModel

from astp.worker_job import WorkerJobEnvelope


class WorkerResultReceipt(BaseModel):
    schema_version: str = "1"
    job_id: str
    action_id: str
    permit_id: str
    evidence_id: str | None = None
    success: bool
    completed_at: datetime
    receipt_hash: str


def _hash(payload: object) -> str:
    raw = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str).encode()
    return hashlib.sha256(raw).hexdigest()


def create_worker_receipt(
    job: WorkerJobEnvelope,
    *,
    success: bool,
    evidence_id: str | None = None,
) -> WorkerResultReceipt:
    completed_at = datetime.now(UTC)
    payload = {
        "job_id": job.id,
        "action_id": job.action_id,
        "permit_id": job.permit_id,
        "evidence_id": evidence_id,
        "success": success,
        "completed_at": completed_at,
    }
    return WorkerResultReceipt(**payload, receipt_hash=_hash(payload))


def verify_worker_receipt(job: WorkerJobEnvelope, receipt: WorkerResultReceipt) -> bool:
    payload = {
        "job_id": receipt.job_id,
        "action_id": receipt.action_id,
        "permit_id": receipt.permit_id,
        "evidence_id": receipt.evidence_id,
        "success": receipt.success,
        "completed_at": receipt.completed_at,
    }
    return (
        receipt.job_id == job.id
        and receipt.action_id == job.action_id
        and receipt.permit_id == job.permit_id
        and _hash(payload) == receipt.receipt_hash
    )
