from datetime import UTC, datetime, timedelta

from astp.authorization import AuthorizationRequest, authorize_test
from astp.frontier import build_frontier
from astp.models import (
    Decision,
    Engagement,
    MethodPolicy,
    OperationalStatus,
    ProgramBinding,
    ProgramOperationalAttestation,
    RiskClass,
    ScopeKind,
    ScopePolicy,
    ScopeRule,
)
from astp.models import (
    TestDefinition as SecurityTestDefinition,
)
from astp.operational_lease import build_operational_lease
from astp.planner import build_observation_plan
from astp.prioritization import prioritize_registry
from astp.target_discovery import (
    CandidateKind,
    CandidateSafety,
    DiscoveryProvenance,
    TargetCandidate,
)
from astp.target_registry import RegistryEntry, TargetRegistry


def _engagement() -> Engagement:
    return Engagement(
        id="e",
        name="E",
        scope=ScopePolicy(
            allowed=[ScopeRule(kind=ScopeKind.WILDCARD_DOMAIN, value="*.example.com")]
        ),
        methods=MethodPolicy(),
        program=ProgramBinding(
            program_id="p",
            platform="bughunt",
            source_content_sha256="a" * 64,
            requires_online=True,
            operational_attestation_max_age_seconds=300,
        ),
    )


def _attestation(observed: datetime) -> ProgramOperationalAttestation:
    return ProgramOperationalAttestation(
        id="att-1",
        program_id="p",
        source_content_sha256="a" * 64,
        status=OperationalStatus.ONLINE,
        observed_at=observed,
        source_type="test",
    )


def _test() -> SecurityTestDefinition:
    return SecurityTestDefinition(
        id="t", title="T", category="observation", risk_class=RiskClass.SAFE_ACTIVE
    )


def _candidate(target: str, *, in_scope: bool = True) -> TargetCandidate:
    return TargetCandidate(
        id="target-" + str(abs(hash(target))),
        canonical_target=target,
        display_target=target,
        kind=CandidateKind.LINK,
        safety=CandidateSafety.READY_FOR_POLICY,
        in_scope=in_scope,
        same_origin=in_scope,
        requires_new_permit=True,
        requires_semantic_assessment=False,
        executable=False,
        reason="ready",
        provenance=[
            DiscoveryProvenance(
                evidence_id="ev",
                source_action_id="a",
                source_target="https://www.example.com/",
                source_kind=CandidateKind.LINK,
                observed_at=datetime(2026, 1, 1, tzinfo=UTC),
            )
        ],
        discovered_at=datetime(2026, 1, 1, tzinfo=UTC),
    )


def _registry() -> TargetRegistry:
    now = datetime(2026, 1, 1, tzinfo=UTC)
    js = _candidate("https://www.example.com/_next/static/chunks/app.js")
    fav = _candidate("https://www.example.com/favicon.svg")
    external = _candidate("https://outside.test/x.js", in_scope=False)
    return TargetRegistry(
        engagement_id="e",
        entries=[
            RegistryEntry(
                canonical_target=js.canonical_target,
                candidate_ids=[js.id],
                provenance=js.provenance,
                latest_candidate=js,
                first_seen_at=now,
                last_seen_at=now,
            ),
            RegistryEntry(
                canonical_target=fav.canonical_target,
                candidate_ids=[fav.id],
                provenance=fav.provenance,
                latest_candidate=fav,
                first_seen_at=now,
                last_seen_at=now,
            ),
            RegistryEntry(
                canonical_target=external.canonical_target,
                candidate_ids=[external.id],
                provenance=external.provenance,
                latest_candidate=external,
                first_seen_at=now,
                last_seen_at=now,
            ),
        ],
        updated_at=now,
    )


def test_stale_attestation_is_allowed_only_with_valid_bounded_lease() -> None:
    engagement = _engagement()
    observed = datetime(2026, 1, 1, 12, 0, tzinfo=UTC)
    attestation = _attestation(observed)
    lease = build_operational_lease(
        engagement,
        attestation,
        assessment_id="assessment-1",
        preflight_report_hash="b" * 64,
        valid_from=observed + timedelta(seconds=30),
        ttl_seconds=1800,
    )
    current = observed + timedelta(minutes=10)
    blocked = authorize_test(
        engagement,
        _test(),
        AuthorizationRequest(
            target="https://www.example.com/a.js",
            http_method="GET",
            requested_requests_per_second=1,
            program_operational_attestation=attestation,
            now=current,
        ),
    )
    assert blocked.decision == Decision.INSUFFICIENT_CONTEXT
    allowed = authorize_test(
        engagement,
        _test(),
        AuthorizationRequest(
            target="https://www.example.com/a.js",
            http_method="GET",
            requested_requests_per_second=1,
            program_operational_attestation=attestation,
            program_operational_lease=lease,
            now=current,
        ),
    )
    assert allowed.decision == Decision.ALLOW
    assert allowed.operational_status_valid_until == lease.valid_until


def test_planner_surfaces_specific_stale_attestation_reason() -> None:
    engagement = _engagement()
    observed = datetime(2026, 1, 1, 12, 0, tzinfo=UTC)
    registry = _registry()
    plan = build_observation_plan(
        registry,
        engagement,
        _test(),
        operational_attestation=_attestation(observed),
        requested_rps=1,
        now=observed + timedelta(minutes=10),
    )
    smart = next(item for item in plan.items if item.target.endswith("app.js"))
    assert "stale" in smart.reason.lower()


def test_priority_prefers_javascript_over_favicon() -> None:
    rows = prioritize_registry(_registry())
    scores = {row.target: row.score for row in rows}
    assert (
        scores["https://www.example.com/_next/static/chunks/app.js"]
        > scores["https://www.example.com/favicon.svg"]
    )


def test_frontier_excludes_out_of_scope_candidates() -> None:
    frontier = build_frontier(_registry(), max_depth=2)
    assert all("outside.test" not in item.target for item in frontier.items)
    assert len(frontier.items) == 2
