from datetime import UTC, datetime

from astp.models import Engagement, ScopeKind, ScopePolicy, ScopeRule
from astp.observation import HttpObservationEvidence, RedirectObservation
from astp.target_discovery import CandidateKind, CandidateSafety, discover_targets_from_evidence


def _engagement() -> Engagement:
    return Engagement(
        id="e1",
        name="Example",
        scope=ScopePolicy(
            allowed=[ScopeRule(kind=ScopeKind.WILDCARD_DOMAIN, value="*.example.com")],
            denied=[],
        ),
    )


def _evidence(redirect: str) -> HttpObservationEvidence:
    return HttpObservationEvidence(
        evidence_id="ev1",
        action_id="act1",
        permit_id="p1",
        engagement_id="e1",
        test_id="observation.http",
        observed_at=datetime.now(UTC),
        method="GET",
        target="https://example.com/",
        status_code=301,
        response_headers={},
        body_sha256="0" * 64,
        redirect=RedirectObservation(
            target=redirect,
            in_scope=True,
            same_origin=False,
        ),
        evidence_hash="1" * 64,
    )


def test_redirect_candidate_never_becomes_executable_implicitly() -> None:
    result = discover_targets_from_evidence(
        _evidence("https://www.example.com/next"), _engagement(), include_links=False
    )
    candidate = result.candidates[0]
    assert candidate.kind == CandidateKind.REDIRECT
    assert candidate.safety == CandidateSafety.READY_FOR_POLICY
    assert candidate.requires_new_permit is True
    assert candidate.executable is False


def test_https_downgrade_is_not_auto_promotable() -> None:
    candidate = discover_targets_from_evidence(
        _evidence("http://www.example.com/"), _engagement(), include_links=False
    ).candidates[0]
    assert candidate.safety == CandidateSafety.HTTPS_DOWNGRADE
    assert candidate.executable is False


def test_private_literal_is_rejected_even_if_scope_could_match() -> None:
    engagement = Engagement(
        id="e1",
        name="literal",
        scope=ScopePolicy(allowed=[ScopeRule(kind=ScopeKind.CIDR, value="127.0.0.0/8")]),
    )
    candidate = discover_targets_from_evidence(
        _evidence("https://127.0.0.1/"), engagement, include_links=False
    ).candidates[0]
    assert candidate.safety == CandidateSafety.PRIVATE_LITERAL
