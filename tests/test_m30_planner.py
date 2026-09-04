from datetime import UTC, datetime

from astp.models import (
    Engagement,
    MethodPolicy,
    ProgramBinding,
    ProgramOperationalAttestation,
    RiskClass,
    ScopeKind,
    ScopePolicy,
    ScopeRule,
)
from astp.models import (
    TestDefinition as RuntimeTestDefinition,
)
from astp.planner import PlanItemStatus, build_observation_plan
from astp.target_discovery import CandidateKind, CandidateSafety, TargetCandidate
from astp.target_registry import RegistryEntry, TargetRegistry


def _registry() -> TargetRegistry:
    now = datetime.now(UTC)
    candidate = TargetCandidate(
        id="c",
        canonical_target="https://www.example.com/",
        display_target="https://www.example.com/",
        kind=CandidateKind.REDIRECT,
        safety=CandidateSafety.READY_FOR_POLICY,
        in_scope=True,
        reason="ok",
        provenance=(),
        discovered_at=now,
    )
    return TargetRegistry(
        engagement_id="e",
        updated_at=now,
        entries=[
            RegistryEntry(
                canonical_target=candidate.canonical_target,
                candidate_ids=[candidate.id],
                provenance=[],
                latest_candidate=candidate,
                first_seen_at=now,
                last_seen_at=now,
            )
        ],
    )


def _engagement() -> Engagement:
    return Engagement(
        id="e",
        name="e",
        scope=ScopePolicy(
            allowed=[ScopeRule(kind=ScopeKind.WILDCARD_DOMAIN, value="*.example.com")]
        ),
        methods=MethodPolicy(),
        program=ProgramBinding(
            program_id="prog",
            platform="test",
            source_content_sha256="a" * 64,
            requires_online=True,
            operational_attestation_max_age_seconds=300,
        ),
    )


def test_planner_blocks_without_fresh_operational_attestation() -> None:
    test = RuntimeTestDefinition(
        id="obs", title="obs", category="observation", risk_class=RiskClass.SAFE_ACTIVE
    )
    plan = build_observation_plan(_registry(), _engagement(), test)
    assert plan.items[0].status == PlanItemStatus.BLOCKED_CONTEXT
    assert plan.items[0].permit_id is None


def test_planner_marks_allow_as_authorizable_not_executable() -> None:
    now = datetime.now(UTC)
    engagement = _engagement()
    attestation = ProgramOperationalAttestation(
        id="op",
        program_id="prog",
        source_content_sha256="a" * 64,
        status="online",
        observed_at=now,
        source_type="operator",
    )
    test = RuntimeTestDefinition(
        id="obs", title="obs", category="observation", risk_class=RiskClass.SAFE_ACTIVE
    )
    plan = build_observation_plan(
        _registry(), engagement, test, operational_attestation=attestation, now=now
    )
    assert plan.items[0].status == PlanItemStatus.AUTHORIZABLE
    assert plan.items[0].requires_new_permit is True
    assert plan.items[0].permit_id is None
