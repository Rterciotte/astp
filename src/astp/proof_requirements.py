from __future__ import annotations

from pydantic import BaseModel, ConfigDict


class ProofRequirement(BaseModel):
    model_config = ConfigDict(frozen=True)
    verifier_id: str
    required_evidence_types: tuple[str, ...]
    requires_distinct_identity: bool = False
    requires_foreign_object_context: bool = False
    automatic_verified_allowed: bool = False


def builtin_proof_requirements() -> tuple[ProofRequirement, ...]:
    return (
        ProofRequirement(
            verifier_id="authorization.object-access.v1",
            required_evidence_types=("http.baseline", "http.comparison"),
            requires_distinct_identity=True,
            requires_foreign_object_context=True,
        ),
        ProofRequirement(
            verifier_id="cors.headers.v1", required_evidence_types=("http.observation",)
        ),
        ProofRequirement(
            verifier_id="tls.posture.v1", required_evidence_types=("tls.observation",)
        ),
        ProofRequirement(
            verifier_id="cookie.flags.v1", required_evidence_types=("http.observation",)
        ),
        ProofRequirement(
            verifier_id="security-headers.csp.v1", required_evidence_types=("http.observation",)
        ),
        ProofRequirement(
            verifier_id="security-headers.hsts.v1", required_evidence_types=("http.observation",)
        ),
        ProofRequirement(
            verifier_id="cache.sensitive-response.v1", required_evidence_types=("http.observation",)
        ),
        ProofRequirement(
            verifier_id="redirect.reauthorization.v1", required_evidence_types=("http.observation",)
        ),
    )
