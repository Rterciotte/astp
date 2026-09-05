from __future__ import annotations

import hashlib

from pydantic import BaseModel, ConfigDict

from astp.verifier_depth import VerifierSignal


class CompiledVerificationAction(BaseModel):
    model_config = ConfigDict(frozen=True)

    id: str
    verifier_id: str
    target: str
    method: str
    state_changing: bool = False
    fresh_permit_required: bool = True
    execution_enabled: bool = False


def compile_verification_action(signal: VerifierSignal) -> CompiledVerificationAction | None:
    if not signal.requires_active_verification:
        return None
    digest = hashlib.sha256(f"{signal.verifier_id}|{signal.target}".encode()).hexdigest()[:16]
    return CompiledVerificationAction(
        id=f"verify-action-{digest}",
        verifier_id=signal.verifier_id,
        target=signal.target,
        method="GET",
    )
