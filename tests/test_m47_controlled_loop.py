from datetime import UTC, datetime

from astp.controlled_loop import run_controlled_queue
from astp.models import (
    Constraints,
    Engagement,
    MethodPolicy,
    RiskClass,
    ScopeKind,
    ScopePolicy,
    ScopeRule,
)
from astp.models import TestDefinition as RuntimeTestDefinition
from astp.policy_snapshot import capture_policy_snapshot
from astp.session_ledger import initialize_session_ledger
from astp.work_queue import WorkQueue, WorkQueueItem


def engagement():
    return Engagement(
        id="e",
        name="e",
        scope=ScopePolicy(allowed=[ScopeRule(kind=ScopeKind.DOMAIN, value="example.com")]),
        methods=MethodPolicy(
            passive="allow",
            safe_active="allow",
            state_changing="approval_required",
            intrusive="deny",
        ),
        constraints=Constraints(max_requests_per_second=1),
    )


def test_controlled_loop_runs_bounded_queue(tmp_path):
    test = RuntimeTestDefinition(
        id="t", title="t", category="observation", risk_class=RiskClass.SAFE_ACTIVE
    )
    queue = WorkQueue(
        created_at=datetime.now(UTC),
        max_active_programs=1,
        items=[
            WorkQueueItem(
                queue_id="q1",
                engagement_id="e",
                test_id="t",
                plan_item_id="p1",
                target="https://example.com/a",
                method="GET",
            ),
            WorkQueueItem(
                queue_id="q2",
                engagement_id="e",
                test_id="t",
                plan_item_id="p2",
                target="https://example.com/b",
                method="GET",
            ),
        ],
    )
    ledger = tmp_path / "ledger.db"
    initialize_session_ledger(ledger, "s")
    result = run_controlled_queue(
        queue,
        engagement(),
        test,
        None,
        capture_policy_snapshot(engagement(), test),
        ledger,
        "s",
        lambda item: (f"permit-{item.queue_id}", f"evidence-{item.queue_id}"),
        max_actions=1,
        max_requests=1,
    )
    assert len(result.outcomes) == 1
    assert result.outcomes[0].completed is True
    assert result.stop_reason == "action budget exhausted"
