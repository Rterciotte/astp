from astp.findings import FindingCandidate, FindingSignal, ProofState, correlate_findings


def test_correlation_merges_sensors_without_inventing_higher_proof_state() -> None:
    rows = [
        FindingCandidate(
            vulnerability="Authorization boundary",
            asset="https://example.com",
            endpoint="/object/1",
            proof_state=ProofState.SUSPECTED,
            signals=[FindingSignal(sensor="http", evidence_id="e1", observation="difference")],
        ),
        FindingCandidate(
            vulnerability="Authorization boundary",
            asset="https://example.com",
            endpoint="/object/1",
            proof_state=ProofState.VERIFIED,
            signals=[FindingSignal(sensor="manual", evidence_id="e2", observation="reproduced")],
        ),
    ]
    result = correlate_findings(rows)
    assert len(result.findings) == 1
    assert result.findings[0].proof_state == ProofState.VERIFIED
    assert len(result.findings[0].signals) == 2
