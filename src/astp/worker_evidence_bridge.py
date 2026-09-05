from __future__ import annotations

import json
from pathlib import Path

from pydantic import BaseModel, ConfigDict

from astp.evidence_store import EvidenceManifestEntry, SensitivityLabel, register_evidence
from astp.worker_protocol import WorkerReceipt
from astp.worker_receipt_evidence import WorkerReceiptEvidence, receipt_to_evidence


class RegisteredWorkerEvidence(BaseModel):
    model_config = ConfigDict(frozen=True)

    receipt_evidence: WorkerReceiptEvidence
    manifest_entry: EvidenceManifestEntry


def register_worker_receipt(
    receipt: WorkerReceipt,
    *,
    manifest_path: Path,
    artifact_directory: Path,
) -> RegisteredWorkerEvidence:
    if not receipt.permit_consumed_before_io:
        raise ValueError("worker receipt cannot enter the evidence store before permit consumption")
    normalized = receipt_to_evidence(receipt)
    artifact_directory.mkdir(parents=True, exist_ok=True)
    artifact_path = artifact_directory / f"{normalized.evidence_id}.json"
    artifact_path.write_text(
        json.dumps(normalized.model_dump(mode="json"), sort_keys=True, indent=2) + "\n",
        encoding="utf-8",
    )
    entry = register_evidence(
        manifest_path,
        artifact_path,
        evidence_type="worker.receipt.v1",
        evidence_id=normalized.evidence_id,
        permit_id=normalized.permit_id,
        action_id=normalized.action_id,
        sensitivity=SensitivityLabel.INTERNAL,
    )
    return RegisteredWorkerEvidence(receipt_evidence=normalized, manifest_entry=entry)
