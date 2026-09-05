from __future__ import annotations

import hashlib
import json

from pydantic import BaseModel, ConfigDict

from astp.worker_receipt_ingestion import WorkerReceiptEnvelope, evaluate_receipt_ingestion


class ReceiptEvidenceArtifact(BaseModel):
    model_config = ConfigDict(frozen=True)
    kind: str = "worker-receipt"
    engagement_id: str
    action_id: str
    permit_id: str
    runtime_id: str
    receipt_hash: str
    artifact_digest: str
    network_io_performed: bool

    def evidence_hash(self) -> str:
        payload = json.dumps(self.model_dump(mode="json"), sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(payload.encode()).hexdigest()


def normalize_receipt_to_evidence(
    receipt: WorkerReceiptEnvelope, *, expected_engagement_id: str, expected_action_id: str
) -> ReceiptEvidenceArtifact:
    decision = evaluate_receipt_ingestion(
        receipt,
        expected_engagement_id=expected_engagement_id,
        expected_action_id=expected_action_id,
    )
    if not decision.accepted:
        raise ValueError("worker receipt failed provenance acceptance")
    return ReceiptEvidenceArtifact(
        engagement_id=receipt.engagement_id,
        action_id=receipt.action_id,
        permit_id=receipt.permit_id,
        runtime_id=receipt.runtime_id,
        receipt_hash=decision.receipt_hash,
        artifact_digest=receipt.artifact_digest,
        network_io_performed=receipt.network_io_performed,
    )
