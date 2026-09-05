from __future__ import annotations

from pydantic import BaseModel, Field

from astp.findings import FindingCandidate, ProofState


class VerificationStep(BaseModel):
    description: str
    expected_evidence: str
    requires_policy_evaluation: bool = True
    requires_new_permit: bool = True


class FindingVerificationPlan(BaseModel):
    finding_key: str
    current_state: ProofState
    target_state: ProofState
    automatic_execution: bool = False
    steps: list[VerificationStep] = Field(default_factory=list)


def build_verification_plan(candidate: FindingCandidate) -> FindingVerificationPlan:
    target = (
        ProofState.LIKELY if candidate.proof_state == ProofState.SUSPECTED else ProofState.VERIFIED
    )
    return FindingVerificationPlan(
        finding_key=f"{candidate.vulnerability}:{candidate.asset}",
        current_state=candidate.proof_state,
        target_state=target,
        steps=[
            VerificationStep(
                description="Collect vulnerability-specific bounded evidence",
                expected_evidence="Integrity-verified evidence satisfying a dedicated proof verifier",
            )
        ],
    )
