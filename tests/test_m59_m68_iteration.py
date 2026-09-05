from datetime import UTC, datetime

import pytest

from astp.action_history import admit_unique_action
from astp.adaptive_method import EscalationReason, choose_followup_method
from astp.depth_frontier import admit_candidate
from astp.evidence_replanner import replan_registry
from astp.fair_scheduler import ProgramQueue, schedule_fair_sessions
from astp.finding_lifecycle import FindingStatus, complete_retest, request_retest
from astp.findings import CorrelatedFinding, FindingCandidate, ProofState
from astp.frontier import CrawlFrontier, FrontierItem
from astp.models import (
    Constraints,
    Engagement,
    MethodPolicy,
    RiskClass,
    ScopeKind,
    ScopePolicy,
    ScopeRule,
)
from astp.models import (
    TestDefinition as RuntimeTestDefinition,
)
from astp.observation import HttpObservationEvidence
from astp.safe_test_catalog import builtin_safe_web_tests
from astp.session_feedback import apply_session_feedback
from astp.target_discovery import (
    CandidateKind,
    CandidateSafety,
    DiscoveryProvenance,
    TargetCandidate,
)
from astp.target_registry import empty_registry
from astp.verification_plan import build_verification_plan
from astp.work_queue import WorkQueueItem
from astp.worker_isolation import WorkerIsolationContract

NOW = datetime.now(UTC)


def candidate(target="https://example.com/a"):
    provenance = DiscoveryProvenance(
        evidence_id="e",
        source_action_id="a",
        source_target="https://example.com/",
        source_kind=CandidateKind.LINK,
        observed_at=NOW,
    )
    return TargetCandidate(
        id="target-a",
        canonical_target=target,
        display_target=target,
        kind=CandidateKind.LINK,
        safety=CandidateSafety.READY_FOR_POLICY,
        in_scope=True,
        same_origin=True,
        reason="safe",
        provenance=(provenance,),
        discovered_at=NOW,
    )


def evidence(method="HEAD", status=200):
    return HttpObservationEvidence(
        evidence_id="e",
        action_id="a",
        permit_id="p",
        engagement_id="eng",
        test_id="test",
        observed_at=NOW,
        method=method,
        target="https://example.com/",
        status_code=status,
        body_sha256="0" * 64,
        evidence_hash="1" * 64,
    )


def queue_item(engagement, suffix):
    return WorkQueueItem(
        queue_id=f"q-{suffix}",
        engagement_id=engagement,
        test_id="t",
        plan_item_id=f"p-{suffix}",
        target=f"https://{engagement}/{suffix}",
        method="HEAD",
    )


def engagement():
    return Engagement(
        id="eng",
        name="example",
        scope=ScopePolicy(allowed=[ScopeRule(kind=ScopeKind.DOMAIN, value="example.com")]),
        methods=MethodPolicy(),
        constraints=Constraints(),
    )


def test_m59_feedback_is_bound_to_session_and_engagement():
    observed = evidence(method="GET").model_copy(
        update={"content_type": "text/html", "body_preview": '<a href="/new">new</a>'}
    )
    result = apply_session_feedback("session-1", observed, engagement(), empty_registry("eng"))
    assert result.session_id == "session-1"
    assert result.added_targets == 1
    with pytest.raises(ValueError, match="different engagements"):
        apply_session_feedback("session-1", observed, engagement(), empty_registry("another"))


def test_m60_replanning_reuses_policy_engine_and_requires_permit():
    observed = evidence(method="GET").model_copy(
        update={"content_type": "text/html", "body_preview": '<a href="/new">new</a>'}
    )
    registry = apply_session_feedback(
        "session-1", observed, engagement(), empty_registry("eng")
    ).registry
    test = RuntimeTestDefinition(
        id="t", title="observe", category="web", risk_class=RiskClass.PASSIVE
    )
    result = replan_registry(registry, engagement(), test)
    assert result.new_authorizable_items == 1
    assert result.plan.items[0].requires_new_permit


def test_m61_depth_admission_is_bounded():
    frontier = CrawlFrontier(
        created_at=NOW,
        max_depth=1,
        items=[FrontierItem(target_id="root", target="https://example.com/", depth=0)],
    )
    admitted = admit_candidate(frontier, candidate(), parent_target_id="root")
    assert admitted.admitted and admitted.frontier.items[-1].depth == 1
    blocked = admit_candidate(
        admitted.frontier, candidate("https://example.com/b"), parent_target_id="target-a"
    )
    assert not blocked.admitted


def test_m62_duplicate_actions_are_suppressed_across_calls(tmp_path):
    arguments = {
        "engagement_id": "e",
        "test_id": "t",
        "target": "https://example.com/",
        "method": "HEAD",
    }
    assert admit_unique_action(tmp_path / "history.db", **arguments).admitted
    assert not admit_unique_action(tmp_path / "history.db", **arguments).admitted


def test_m63_head_escalates_only_when_body_is_required():
    decision = choose_followup_method(evidence(), body_evidence_required=True)
    assert decision.method == "GET" and decision.requires_new_permit
    assert (
        choose_followup_method(evidence(), body_evidence_required=False).reason
        == EscalationReason.METADATA_SUFFICIENT
    )


def test_m64_catalog_contains_only_bounded_permit_gated_tests():
    catalog = builtin_safe_web_tests()
    assert {item.kind.value for item in catalog} == {"headers", "cookies", "cors", "tls"}
    assert all(item.requires_execution_permit and not item.state_changing for item in catalog)
    assert all(item.risk_class in {RiskClass.PASSIVE, RiskClass.SAFE_ACTIVE} for item in catalog)


def test_m65_verification_plan_does_not_auto_execute():
    plan = build_verification_plan(FindingCandidate(vulnerability="CSP", asset="example.com"))
    assert not plan.automatic_execution
    assert all(step.requires_policy_evaluation and step.requires_new_permit for step in plan.steps)


def test_m66_finding_retest_lifecycle():
    finding = CorrelatedFinding(
        id="f",
        vulnerability="CSP",
        asset="example.com",
        proof_state=ProofState.VERIFIED,
        created_at=NOW,
    )
    pending = request_retest(finding)
    assert complete_retest(pending, still_present=False).status == FindingStatus.RESOLVED


def test_m67_scheduler_round_robins_programs():
    rows = schedule_fair_sessions(
        [
            ProgramQueue(engagement_id="a", items=[queue_item("a", "1"), queue_item("a", "2")]),
            ProgramQueue(engagement_id="b", items=[queue_item("b", "1"), queue_item("b", "2")]),
        ]
    )
    assert [row.engagement_id for row in rows] == ["a", "b", "a", "b"]


def test_m68_isolation_rejects_signing_keys_and_unpermitted_network():
    with pytest.raises(ValueError, match="signing keys"):
        WorkerIsolationContract(
            adapter_id="a", container_image="a@sha256:1", receives_signing_key=True
        )
    with pytest.raises(ValueError, match="must require"):
        WorkerIsolationContract(
            adapter_id="a",
            container_image="a@sha256:1",
            network_enabled=True,
            requires_execution_permit=False,
        )
