from astp.findings import CorrelatedFinding, FindingSet, ProofState
from astp.models import Engagement, ScopePolicy
from astp.reporting import render_markdown_report


def test_report_contains_proof_state_and_permit_gated_retest() -> None:
    engagement = Engagement(id="e", name="Example", scope=ScopePolicy())
    findings = FindingSet(
        findings=[
            CorrelatedFinding(
                id="finding-1",
                vulnerability="Example issue",
                asset="https://example.com",
                proof_state=ProofState.VERIFIED,
                created_at="2026-09-04T00:00:00+00:00",
            )
        ]
    )
    report = render_markdown_report(engagement, findings)
    assert "VERIFIED" in report
    assert "fresh execution permit" in report
    assert "Retest `finding-1`" in report
