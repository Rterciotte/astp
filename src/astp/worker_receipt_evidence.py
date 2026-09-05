from __future__ import annotations

import hashlib
import json

from pydantic import BaseModel, ConfigDict

from astp.worker_protocol import WorkerReceipt


class WorkerReceiptEvidence(BaseModel):
    model_config = ConfigDict(frozen=True)

    evidence_id: str
    request_id: str
    permit_id: str
    action_id: str
    operation: str
    receipt_sha256: str
    permit_consumed_before_io: bool
    network_io_performed: bool
    output_truncated: bool


def receipt_to_evidence(receipt: WorkerReceipt) -> WorkerReceiptEvidence:
    payload = json.dumps(receipt.model_dump(mode="json"), sort_keys=True, separators=(",", ":"))
    digest = hashlib.sha256(payload.encode("utf-8")).hexdigest()
    return WorkerReceiptEvidence(
        evidence_id=f"worker-receipt-{digest[:16]}",
        request_id=receipt.request_id,
        permit_id=receipt.permit_id,
        action_id=receipt.action_id,
        operation=receipt.operation.value,
        receipt_sha256=digest,
        permit_consumed_before_io=receipt.permit_consumed_before_io,
        network_io_performed=receipt.network_io_performed,
        output_truncated=receipt.output_truncated,
    )
