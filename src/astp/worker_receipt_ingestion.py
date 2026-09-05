from __future__ import annotations

import hashlib
import json

from pydantic import BaseModel, ConfigDict, Field


class WorkerReceiptEnvelope(BaseModel):
    model_config = ConfigDict(frozen=True)

    runtime_id: str
    engagement_id: str
    permit_id: str
    action_id: str
    artifact_digest: str
    permit_consumed_before_io: bool
    network_io_performed: bool
    stdout_digest: str | None = None
    stderr_digest: str | None = None
    output_truncated: bool = False

    def receipt_hash(self) -> str:
        payload = json.dumps(self.model_dump(mode="json"), sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()


class ReceiptIngestionDecision(BaseModel):
    model_config = ConfigDict(frozen=True)

    accepted: bool
    receipt_hash: str
    reasons: tuple[str, ...] = Field(default_factory=tuple)


def evaluate_receipt_ingestion(
    receipt: WorkerReceiptEnvelope,
    *,
    expected_engagement_id: str,
    expected_action_id: str,
) -> ReceiptIngestionDecision:
    reasons: list[str] = []
    if receipt.engagement_id != expected_engagement_id:
        reasons.append("receipt engagement does not match assessment")
    if receipt.action_id != expected_action_id:
        reasons.append("receipt action_id does not match expected action")
    if not receipt.permit_consumed_before_io:
        reasons.append("receipt does not prove permit consumption before I/O")
    if not receipt.artifact_digest.startswith("sha256:"):
        reasons.append("receipt artifact digest is not sha256-bound")
    return ReceiptIngestionDecision(
        accepted=not reasons,
        receipt_hash=receipt.receipt_hash(),
        reasons=tuple(reasons),
    )
