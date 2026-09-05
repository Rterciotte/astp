from __future__ import annotations

import hashlib

from pydantic import BaseModel, ConfigDict, Field

from astp.verification_planner import VerificationActionProposal, propose_verification_action
from astp.verifier_depth import VerifierSignal


class VerificationBatch(BaseModel):
    model_config = ConfigDict(frozen=True)

    id: str
    proposals: tuple[VerificationActionProposal, ...] = Field(default_factory=tuple)
    fresh_permit_per_action: bool = True
    execution_enabled: bool = False


def build_verification_batch(signals: tuple[VerifierSignal, ...]) -> VerificationBatch:
    proposals = tuple(propose_verification_action(item) for item in signals)
    digest = hashlib.sha256("|".join(item.id for item in proposals).encode()).hexdigest()[:16]
    return VerificationBatch(id=f"verify-batch-{digest}", proposals=proposals)
