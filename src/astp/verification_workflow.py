from __future__ import annotations

import hashlib
from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field

from astp.active_verifier_registry import (
    ActiveVerifierDefinition,
    ActiveVerifierRisk,
    builtin_active_verifiers,
)
from astp.assessment import load_evidence_directory
from astp.verification_batch import VerificationBatch, build_verification_batch
from astp.verifier_depth import VerifierSignal, verify_stored_http_evidence


class VerificationWorkflow(BaseModel):
    model_config = ConfigDict(frozen=True)

    id: str
    evidence_records: int
    signals: tuple[VerifierSignal, ...] = Field(default_factory=tuple)
    batch: VerificationBatch
    active_verifiers: tuple[ActiveVerifierDefinition, ...] = Field(default_factory=tuple)
    state_changing_verifiers: tuple[str, ...] = Field(default_factory=tuple)
    execution_enabled: bool = False
    network_performed: bool = False


def plan_verification_workflow(evidence_directory: Path) -> VerificationWorkflow:
    evidence = load_evidence_directory(evidence_directory)
    signals = tuple(signal for item in evidence for signal in verify_stored_http_evidence(item))
    batch = build_verification_batch(signals)
    verifiers = builtin_active_verifiers()
    state_changing = tuple(
        item.id for item in verifiers if item.risk is ActiveVerifierRisk.STATE_CHANGING
    )
    raw = "|".join([*(item.evidence_id for item in evidence), *(item.id for item in signals)])
    digest = hashlib.sha256(raw.encode()).hexdigest()[:16]
    return VerificationWorkflow(
        id=f"verification-workflow-{digest}",
        evidence_records=len(evidence),
        signals=signals,
        batch=batch,
        active_verifiers=verifiers,
        state_changing_verifiers=state_changing,
    )
