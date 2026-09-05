from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel, ConfigDict

from astp.differential_analysis import DifferentialComparison


class AuthorizationProofState(StrEnum):
    INSUFFICIENT = "insufficient"
    SUSPECTED = "suspected"
    LIKELY = "likely"


class AuthorizationVerification(BaseModel):
    model_config = ConfigDict(frozen=True)

    state: AuthorizationProofState
    confidence: float
    verified_vulnerability: bool = False
    requires_object_ownership_context: bool = True
    rationale: tuple[str, ...]


def verify_authorization_comparison(
    comparison: DifferentialComparison,
    *,
    foreign_object_confirmed: bool,
) -> AuthorizationVerification:
    if not comparison.authorization_boundary_signal:
        return AuthorizationVerification(
            state=AuthorizationProofState.INSUFFICIENT,
            confidence=comparison.confidence,
            rationale=("differential responses do not establish a boundary issue",),
        )
    if not foreign_object_confirmed:
        return AuthorizationVerification(
            state=AuthorizationProofState.SUSPECTED,
            confidence=comparison.confidence,
            rationale=("similar access observed, but foreign-object ownership is not established",),
        )
    return AuthorizationVerification(
        state=AuthorizationProofState.LIKELY,
        confidence=comparison.confidence,
        rationale=("distinct identities produced equivalent access to a confirmed foreign object",),
    )
