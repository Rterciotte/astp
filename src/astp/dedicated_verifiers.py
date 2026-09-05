from __future__ import annotations

from astp.findings import FindingCandidate, ProofState
from astp.observation import HttpObservationEvidence
from astp.proof_verifier import ProofVerification


def verify_cors_headers(
    candidate: FindingCandidate,
    evidence_by_id: dict[str, HttpObservationEvidence],
) -> ProofVerification:
    matched = []
    for signal in candidate.signals:
        evidence = evidence_by_id.get(signal.evidence_id)
        if evidence is None:
            continue
        headers = {key.lower(): value for key, value in evidence.response_headers.items()}
        origin = headers.get("access-control-allow-origin")
        credentials = headers.get("access-control-allow-credentials", "").lower()
        if origin == "*" and credentials == "true":
            matched.append(evidence.evidence_id)
    if not matched:
        return ProofVerification(
            valid=False,
            candidate=candidate,
            maximum_supported_state=ProofState.SUSPECTED,
            reason="Dedicated CORS header condition was not reproduced in supplied evidence.",
        )
    return ProofVerification(
        valid=True,
        candidate=candidate,
        maximum_supported_state=ProofState.LIKELY,
        reason="Stored evidence reproduces the suspicious CORS header combination.",
        evidence_ids=sorted(set(matched)),
    )
