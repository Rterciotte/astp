from datetime import UTC, datetime

from astp.planner import ObservationPlan, ObservationPlanItem, PlanItemStatus
from astp.work_queue import build_fair_work_queue


def _plan(engagement_id: str, targets: list[str]) -> ObservationPlan:
    return ObservationPlan(
        engagement_id=engagement_id,
        test_id="obs",
        created_at=datetime.now(UTC),
        items=[
            ObservationPlanItem(
                id=f"p-{index}",
                target=target,
                status=PlanItemStatus.AUTHORIZABLE,
                reason="ok",
            )
            for index, target in enumerate(targets)
        ],
    )


def test_queue_round_robins_programs_and_keeps_permit_boundary() -> None:
    queue = build_fair_work_queue(
        [_plan("a", ["https://a/1", "https://a/2"]), _plan("b", ["https://b/1"])],
        max_active_programs=2,
    )
    assert [item.engagement_id for item in queue.items] == ["a", "b", "a"]
    assert all(item.requires_new_permit for item in queue.items)
