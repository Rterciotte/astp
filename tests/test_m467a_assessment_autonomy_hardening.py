from datetime import UTC, datetime, timedelta

import pytest

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
from astp.operational_lease import (
    OperationalLeaseStore,
    ProgramOperationalLease,
    _canonical_hash,
    build_operational_lease,
    lease_is_valid,
)
from astp.permits import issue_execution_permit
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


def test_stale_attestation_is_allowed_only_with_valid_bounded_lease(tmp_path) -> None:
    engagement = _engagement()
    observed = datetime(2026, 1, 1, 12, 0, tzinfo=UTC)
    attestation = _attestation(observed)
    store = OperationalLeaseStore(tmp_path / "leases.json")
    lease = store.issue(
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
            operational_lease_store_path=str(store.path),
            now=current,
        ),
    )
    assert allowed.decision == Decision.ALLOW
    assert allowed.operational_status_valid_until == lease.valid_until
    permit_now = current + timedelta(minutes=10)
    permit = issue_execution_permit(
        engagement,
        _test(),
        AuthorizationRequest(
            target="https://www.example.com/a.js",
            http_method="GET",
            requested_requests_per_second=1,
            program_operational_attestation=attestation,
            program_operational_lease=lease,
            operational_lease_store_path=str(store.path),
            now=permit_now,
        ),
        "x" * 32,
        ttl_seconds=900,
        now=permit_now,
    )
    assert permit.payload.expires_at == lease.valid_until


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


@pytest.mark.parametrize(
    ("start_seconds", "duration_seconds", "schema"),
    [(0, 1801, "1"), (0, 29, "1"), (300, 1800, "1"), (-31, 1800, "1"), (0, 1800, "2")],
)
def test_rehashed_persisted_lease_cannot_bypass_issuance_constraints(
    start_seconds, duration_seconds, schema
) -> None:
    observed = datetime(2026, 1, 1, tzinfo=UTC)
    engagement, attestation = _engagement(), _attestation(observed)
    lease = build_operational_lease(
        engagement,
        attestation,
        assessment_id="assessment-1",
        preflight_report_hash="b" * 64,
        valid_from=observed,
    )
    payload = lease.model_dump(mode="json", exclude={"id", "lease_hash"})
    start = observed + timedelta(seconds=start_seconds)
    payload.update(
        valid_from=start.isoformat(),
        valid_until=(start + timedelta(seconds=duration_seconds)).isoformat(),
        attestation_observed_at=observed.isoformat(),
        schema_version=schema,
    )
    digest = _canonical_hash(payload)
    recovered = ProgramOperationalLease.model_validate(
        dict(payload, id=f"oplease-{digest[:12]}", lease_hash=digest)
    )
    assert not lease_is_valid(recovered, engagement, attestation, now=start)[0]
    result = authorize_test(
        engagement,
        _test(),
        AuthorizationRequest(
            target="https://www.example.com/a.js",
            http_method="GET",
            requested_requests_per_second=1,
            program_operational_attestation=attestation,
            program_operational_lease=recovered,
            now=observed + timedelta(minutes=10),
        ),
    )
    assert result.decision == Decision.INSUFFICIENT_CONTEXT


@pytest.mark.parametrize("field", ["assessment_id", "preflight_report_hash"])
@pytest.mark.parametrize("value", ["", " \t\n"])
def test_lease_rejects_missing_bindings_at_issuance_and_recovery(field, value) -> None:
    observed = datetime(2026, 1, 1, tzinfo=UTC)
    engagement, attestation = _engagement(), _attestation(observed)
    bindings = {"assessment_id": "assessment-1", "preflight_report_hash": "b" * 64}
    with pytest.raises(ValueError, match="requires assessment and preflight bindings"):
        build_operational_lease(
            engagement, attestation, valid_from=observed, **dict(bindings, **{field: value})
        )
    lease = build_operational_lease(engagement, attestation, valid_from=observed, **bindings)
    payload = lease.model_dump(mode="json", exclude={"id", "lease_hash"})
    payload[field] = value
    digest = _canonical_hash(payload)
    recovered = ProgramOperationalLease.model_validate_json(
        ProgramOperationalLease.model_validate(
            dict(payload, id=f"oplease-{digest[:12]}", lease_hash=digest)
        ).model_dump_json()
    )
    valid, reason = lease_is_valid(recovered, engagement, attestation, now=observed)
    assert not valid
    assert reason == "operational lease requires assessment and preflight bindings"


def test_recovered_lease_expiry_revision_and_clock_validation() -> None:
    observed = datetime(2026, 1, 1, tzinfo=UTC)
    engagement, attestation = _engagement(), _attestation(observed)
    lease = build_operational_lease(
        engagement,
        attestation,
        assessment_id="assessment-1",
        preflight_report_hash="b" * 64,
        valid_from=observed,
    )
    recovered = ProgramOperationalLease.model_validate_json(lease.model_dump_json())
    assert lease_is_valid(recovered, engagement, attestation, now=observed)[0]
    assert not lease_is_valid(recovered, engagement, attestation, now=lease.valid_until)[0]
    assert not lease_is_valid(
        recovered, engagement, attestation, now=observed.replace(tzinfo=None)
    )[0]
    revised = engagement.model_copy(
        update={
            "program": engagement.program.model_copy(update={"source_content_sha256": "c" * 64})
        }
    )
    assert not lease_is_valid(recovered, revised, attestation, now=observed)[0]


@pytest.mark.parametrize("seconds_before_start", [30, 1, 0.000001])
def test_recovered_lease_is_inactive_before_start(seconds_before_start: float) -> None:
    observed = datetime(2026, 1, 1, tzinfo=UTC)
    engagement, attestation = _engagement(), _attestation(observed)
    lease = build_operational_lease(
        engagement,
        attestation,
        assessment_id="assessment-1",
        preflight_report_hash="b" * 64,
        valid_from=observed + timedelta(seconds=299),
    )
    recovered = ProgramOperationalLease.model_validate_json(lease.model_dump_json())
    current = lease.valid_from - timedelta(seconds=seconds_before_start)
    valid, reason = lease_is_valid(recovered, engagement, attestation, now=current)
    assert not valid
    assert reason == "operational lease is not active yet"
    result = authorize_test(
        engagement,
        _test(),
        AuthorizationRequest(
            target="https://www.example.com/a.js",
            http_method="GET",
            requested_requests_per_second=1,
            program_operational_attestation=attestation,
            program_operational_lease=recovered,
            now=current,
        ),
    )
    # Fresh attestation remains independently valid; the future lease must not
    # extend the authorization lifetime before it activates.
    assert result.decision == Decision.ALLOW
    assert result.operational_status_valid_until == observed + timedelta(seconds=300)
    assert lease_is_valid(recovered, engagement, attestation, now=lease.valid_from)[0]
    assert lease_is_valid(
        recovered,
        engagement,
        attestation,
        now=lease.valid_until - timedelta(microseconds=1),
    )[0]
    assert not lease_is_valid(recovered, engagement, attestation, now=lease.valid_until)[0]


def test_durable_lease_lifecycle_renewal_revocation_and_recovery(tmp_path) -> None:
    observed = datetime(2026, 1, 1, tzinfo=UTC)
    engagement, attestation = _engagement(), _attestation(observed)
    path = tmp_path / "operational-leases.json"
    store = OperationalLeaseStore(path)
    lease = store.issue(
        engagement,
        attestation,
        assessment_id="assessment-1",
        preflight_report_hash="b" * 64,
        valid_from=observed,
        ttl_seconds=300,
    )
    recovered_store = OperationalLeaseStore(path)
    recovered = recovered_store.recover(lease.id)
    recovered_store.require_valid(recovered, engagement, attestation, now=observed)

    renewed = recovered_store.renew(
        lease.id,
        engagement,
        attestation,
        valid_from=observed + timedelta(seconds=60),
        ttl_seconds=240,
    )
    with pytest.raises(ValueError, match="not active"):
        recovered_store.require_valid(
            lease, engagement, attestation, now=observed + timedelta(seconds=61)
        )
    recovered_store.require_valid(
        renewed, engagement, attestation, now=observed + timedelta(seconds=61)
    )
    recovered_store.revoke(renewed.id)
    with pytest.raises(ValueError, match="not active"):
        OperationalLeaseStore(path).require_valid(
            renewed, engagement, attestation, now=observed + timedelta(seconds=62)
        )


def test_durable_store_never_revives_expired_or_revision_changed_lease(tmp_path) -> None:
    observed = datetime(2026, 1, 1, tzinfo=UTC)
    engagement, attestation = _engagement(), _attestation(observed)
    store = OperationalLeaseStore(tmp_path / "leases.json")
    lease = store.issue(
        engagement,
        attestation,
        assessment_id="assessment-1",
        preflight_report_hash="b" * 64,
        valid_from=observed,
        ttl_seconds=30,
    )
    with pytest.raises(ValueError, match="stale"):
        OperationalLeaseStore(store.path).require_valid(
            lease, engagement, attestation, now=observed + timedelta(seconds=30)
        )
    revised = engagement.model_copy(
        update={
            "program": engagement.program.model_copy(update={"source_content_sha256": "d" * 64})
        }
    )
    with pytest.raises(ValueError, match="different program revision"):
        store.require_valid(lease, revised, attestation, now=observed)


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
