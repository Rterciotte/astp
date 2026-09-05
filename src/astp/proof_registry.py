from __future__ import annotations

from collections.abc import Callable

from pydantic import BaseModel, Field

from astp.findings import FindingCandidate, ProofState
from astp.observation import HttpObservationEvidence
from astp.proof_verifier import ProofVerification, verify_finding_candidate


class ProofVerifierSpec(BaseModel):
    id: str
    finding_prefix: str
    maximum_state: ProofState
    automatic_execution: bool = False
    requires_dedicated_evidence: bool = True


class ProofVerifierRegistry(BaseModel):
    specs: list[ProofVerifierSpec] = Field(default_factory=list)


def builtin_proof_registry() -> ProofVerifierRegistry:
    return ProofVerifierRegistry(
        specs=[
            ProofVerifierSpec(
                id="cors.headers.v1",
                finding_prefix="protocol.cors_",
                maximum_state=ProofState.LIKELY,
            )
        ]
    )


def select_proof_verifier(
    candidate: FindingCandidate, registry: ProofVerifierRegistry | None = None
) -> ProofVerifierSpec | None:
    current = registry or builtin_proof_registry()
    key = candidate.vulnerability.lower()
    return next((spec for spec in current.specs if key.startswith(spec.finding_prefix)), None)


def verify_with_registry(
    candidate: FindingCandidate,
    evidence_by_id: dict[str, HttpObservationEvidence],
    *,
    registry: ProofVerifierRegistry | None = None,
    dedicated_verifiers: (
        dict[
            str, Callable[[FindingCandidate, dict[str, HttpObservationEvidence]], ProofVerification]
        ]
        | None
    ) = None,
) -> ProofVerification:
    spec = select_proof_verifier(candidate, registry)
    if spec is None:
        return verify_finding_candidate(candidate, evidence_by_id)
    verifier = (dedicated_verifiers or {}).get(spec.id)
    if verifier is None:
        generic = verify_finding_candidate(candidate, evidence_by_id)
        maximum = min(
            (generic.maximum_supported_state, spec.maximum_state),
            key=lambda state: {
                ProofState.SUSPECTED: 0,
                ProofState.LIKELY: 1,
                ProofState.VERIFIED: 2,
                ProofState.IMPACT_CONFIRMED: 3,
            }[state],
        )
        return generic.model_copy(update={"valid": False, "maximum_supported_state": maximum})
    return verifier(candidate, evidence_by_id)
