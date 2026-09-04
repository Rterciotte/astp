from __future__ import annotations

from enum import Enum

from pydantic import BaseModel, Field

from astp.findings import FindingCandidate, ProofState
from astp.observation import HttpObservationEvidence, verify_observation_evidence


class ProofCheckState(str, Enum):
    PASS = "pass"
    FAIL = "fail"
    REVIEW = "review"


class ProofCheck(BaseModel):
    name: str
    state: ProofCheckState
    message: str


class ProofVerification(BaseModel):
    valid: bool
    maximum_supported_state: ProofState
    checks: list[ProofCheck] = Field(default_factory=list)


def verify_finding_candidate(
    candidate: FindingCandidate,
    evidence_by_id: dict[str, HttpObservationEvidence],
) -> ProofVerification:
    checks: list[ProofCheck] = []
    if not candidate.signals:
        checks.append(
            ProofCheck(
                name="signals",
                state=ProofCheckState.REVIEW,
                message="No evidence signals supplied.",
            )
        )
        maximum = ProofState.SUSPECTED
    else:
        unknown = [
            signal.evidence_id
            for signal in candidate.signals
            if signal.evidence_id not in evidence_by_id
        ]
        if unknown:
            checks.append(
                ProofCheck(
                    name="evidence_presence",
                    state=ProofCheckState.FAIL,
                    message="Missing evidence IDs: " + ", ".join(sorted(set(unknown))),
                )
            )
            return ProofVerification(
                valid=False,
                maximum_supported_state=ProofState.SUSPECTED,
                checks=checks,
            )
        invalid = [
            evidence_id
            for evidence_id, evidence in evidence_by_id.items()
            if any(signal.evidence_id == evidence_id for signal in candidate.signals)
            and not verify_observation_evidence(evidence)
        ]
        if invalid:
            checks.append(
                ProofCheck(
                    name="evidence_integrity",
                    state=ProofCheckState.FAIL,
                    message="Evidence hash verification failed: " + ", ".join(sorted(invalid)),
                )
            )
            return ProofVerification(
                valid=False,
                maximum_supported_state=ProofState.SUSPECTED,
                checks=checks,
            )
        checks.append(
            ProofCheck(
                name="evidence_integrity",
                state=ProofCheckState.PASS,
                message="All referenced observation evidence has valid hashes.",
            )
        )
        unique_evidence = {signal.evidence_id for signal in candidate.signals}
        maximum = ProofState.LIKELY if len(unique_evidence) >= 2 else ProofState.SUSPECTED

    if candidate.proof_state in {ProofState.VERIFIED, ProofState.IMPACT_CONFIRMED}:
        checks.append(
            ProofCheck(
                name="proof_state",
                state=ProofCheckState.REVIEW,
                message=(
                    "VERIFIED/IMPACT_CONFIRMED requires a vulnerability-specific proof verifier; "
                    "generic observation evidence alone cannot establish it."
                ),
            )
        )
        return ProofVerification(valid=False, maximum_supported_state=maximum, checks=checks)
    supported = candidate.proof_state in {ProofState.SUSPECTED, maximum}
    checks.append(
        ProofCheck(
            name="proof_state",
            state=ProofCheckState.PASS if supported else ProofCheckState.REVIEW,
            message=f"Generic verifier supports at most {maximum.value} for this candidate.",
        )
    )
    return ProofVerification(valid=supported, maximum_supported_state=maximum, checks=checks)
