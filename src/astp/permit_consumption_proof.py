from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path

from pydantic import BaseModel, ConfigDict

from astp.lifecycle import PermitLifecycleStatus, consume_execution_permit
from astp.models import Engagement, TestDefinition
from astp.permits import PermitVerificationRequest, SignedExecutionPermit
from astp.worker_protocol import WorkerRequest


class PermitConsumptionProof(BaseModel):
    """Exact-action proof emitted only after lifecycle consumption succeeds."""

    model_config = ConfigDict(frozen=True)

    permit_id: str
    engagement_id: str
    test_id: str
    target: str
    action_id: str
    consumed_at: datetime
    permit_signature_sha256: str
    lifecycle_status: PermitLifecycleStatus = PermitLifecycleStatus.CONSUMED

    def binding_hash(self) -> str:
        raw = json.dumps(self.model_dump(mode="json"), sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def consume_worker_request_permit(
    permit: SignedExecutionPermit,
    worker_request: WorkerRequest,
    engagement: Engagement,
    test: TestDefinition,
    keys: str | bytes,
    *,
    state_path: Path,
    now: datetime | None = None,
) -> PermitConsumptionProof:
    """Verify exact bindings, consume once, then return a typed launch proof."""
    if permit.payload.engagement_id != engagement.id:
        raise ValueError("permit engagement does not match the active engagement")
    if permit.payload.test_id != test.id:
        raise ValueError("permit test does not match the active test")
    if worker_request.engagement_id != engagement.id:
        raise ValueError("worker request engagement does not match the active engagement")
    if worker_request.permit_id != permit.payload.permit_id:
        raise ValueError("worker request permit_id does not match the signed permit")
    if worker_request.target != permit.payload.target:
        raise ValueError("worker request target does not match the signed permit")
    if not worker_request.action_id.strip():
        raise ValueError("worker request action_id is required")

    current = now or datetime.now(UTC)
    verification_request = PermitVerificationRequest(
        target=worker_request.target,
        http_method=permit.payload.http_method,
        identity=permit.payload.identity,
        requested_requests_per_second=permit.payload.max_requests_per_second,
        now=current,
    )
    result = consume_execution_permit(
        permit,
        engagement,
        test,
        verification_request,
        keys,
        state_path,
    )
    if not result.accepted or result.lifecycle_status != PermitLifecycleStatus.CONSUMED:
        raise ValueError(f"permit consumption failed: {result.message}")

    signature_hash = hashlib.sha256(permit.signature.encode("utf-8")).hexdigest()
    return PermitConsumptionProof(
        permit_id=permit.payload.permit_id,
        engagement_id=engagement.id,
        test_id=test.id,
        target=worker_request.target,
        action_id=worker_request.action_id,
        consumed_at=current,
        permit_signature_sha256=signature_hash,
    )
