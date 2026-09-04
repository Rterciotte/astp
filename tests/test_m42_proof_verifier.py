from astp.findings import FindingCandidate, FindingSignal, ProofState
from astp.proof_verifier import verify_finding_candidate


def test_verified_state_not_granted_by_generic_verifier():
    candidate = FindingCandidate(
        vulnerability="x", asset="a", proof_state=ProofState.VERIFIED, signals=[]
    )
    result = verify_finding_candidate(candidate, {})
    assert not result.valid
    assert result.maximum_supported_state == ProofState.SUSPECTED


def test_missing_evidence_fails():
    candidate = FindingCandidate(
        vulnerability="x",
        asset="a",
        signals=[FindingSignal(sensor="s", evidence_id="missing", observation="o")],
    )
    assert not verify_finding_candidate(candidate, {}).valid
