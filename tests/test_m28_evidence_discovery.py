from datetime import UTC, datetime

from astp.models import Engagement, ScopeKind, ScopePolicy, ScopeRule
from astp.observation import HttpObservationEvidence
from astp.target_discovery import CandidateKind, CandidateSafety, discover_targets_from_evidence


def test_body_preview_link_discovery_is_bounded_and_non_executing() -> None:
    engagement = Engagement(
        id="e",
        name="e",
        scope=ScopePolicy(
            allowed=[ScopeRule(kind=ScopeKind.WILDCARD_DOMAIN, value="*.example.com")]
        ),
    )
    evidence = HttpObservationEvidence(
        evidence_id="ev",
        action_id="a",
        permit_id="p",
        engagement_id="e",
        test_id="t",
        observed_at=datetime.now(UTC),
        method="GET",
        target="https://www.example.com/root",
        status_code=200,
        response_headers={},
        body_sha256="0" * 64,
        body_preview='<a href="/a">A</a><img src="https://cdn.example.com/i.png">',
        evidence_hash="1" * 64,
    )
    result = discover_targets_from_evidence(evidence, engagement, max_link_candidates=1)
    assert len(result.candidates) == 1
    assert result.candidates[0].kind == CandidateKind.LINK
    assert result.candidates[0].safety == CandidateSafety.READY_FOR_POLICY
    assert result.candidates[0].executable is False
