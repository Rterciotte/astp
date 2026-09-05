from datetime import UTC, datetime

from astp.feedback import apply_evidence_feedback
from astp.models import Constraints, Engagement, MethodPolicy, ScopeKind, ScopePolicy, ScopeRule
from astp.observation import HttpObservationEvidence, RedirectObservation
from astp.target_registry import empty_registry


def test_feedback_adds_redirect_candidate():
    engagement = Engagement(
        id="e",
        name="e",
        scope=ScopePolicy(allowed=[ScopeRule(kind=ScopeKind.DOMAIN, value="example.com")]),
        methods=MethodPolicy(),
        constraints=Constraints(),
    )
    evidence = HttpObservationEvidence(
        evidence_id="ev",
        action_id="a",
        permit_id="p",
        engagement_id="e",
        test_id="t",
        observed_at=datetime.now(UTC),
        method="GET",
        target="https://example.com/",
        status_code=301,
        body_sha256="0" * 64,
        evidence_hash="1" * 64,
        redirect=RedirectObservation(
            target="https://www.example.com/", in_scope=True, same_origin=False
        ),
    )
    result = apply_evidence_feedback(evidence, engagement, empty_registry("e"), include_links=False)
    assert result.added_entries == 1
    assert result.registry.entries[0].canonical_target == "https://www.example.com/"
