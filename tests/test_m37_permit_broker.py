from datetime import UTC, datetime

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
from astp.permit_broker import broker_queue_item_permit
from astp.work_queue import WorkQueueItem


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


def test_broker_binds_exact_queue_action():
    item = WorkQueueItem(
        queue_id="q",
        engagement_id="e",
        test_id="t",
        plan_item_id="p",
        target="https://example.com/",
        method="GET",
    )
    test = RuntimeTestDefinition(
        id="t", title="t", category="observation", risk_class=RiskClass.SAFE_ACTIVE
    )
    receipt = broker_queue_item_permit(
        item, engagement(), test, "x" * 40, requested_rps=1, now=datetime.now(UTC)
    )
    assert receipt.permit.payload.target == item.target
    assert receipt.permit.payload.http_method == "GET"


def test_broker_rejects_cross_engagement_item():
    item = WorkQueueItem(
        queue_id="q",
        engagement_id="other",
        test_id="t",
        plan_item_id="p",
        target="https://example.com/",
        method="GET",
    )
    test = RuntimeTestDefinition(
        id="t", title="t", category="observation", risk_class=RiskClass.SAFE_ACTIVE
    )
    try:
        broker_queue_item_permit(item, engagement(), test, "x" * 40, requested_rps=1)
    except ValueError as exc:
        assert "different engagement" in str(exc)
    else:
        raise AssertionError("expected ValueError")
