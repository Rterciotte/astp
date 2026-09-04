from __future__ import annotations

from datetime import UTC, datetime

from pydantic import BaseModel, Field

from astp.planner import ObservationPlan, PlanItemStatus


class WorkQueueItem(BaseModel):
    queue_id: str
    engagement_id: str
    test_id: str
    plan_item_id: str
    target: str
    method: str
    requires_new_permit: bool = True


class WorkQueue(BaseModel):
    schema_version: str = "1"
    created_at: datetime
    max_active_programs: int
    items: list[WorkQueueItem] = Field(default_factory=list)


def build_fair_work_queue(
    plans: list[ObservationPlan],
    *,
    max_active_programs: int = 4,
    max_items: int = 100,
    now: datetime | None = None,
) -> WorkQueue:
    if max_active_programs < 1:
        raise ValueError("max_active_programs must be at least 1")
    if max_items < 1:
        raise ValueError("max_items must be at least 1")

    eligible: list[tuple[ObservationPlan, list]] = []
    for plan in plans:
        rows = [item for item in plan.items if item.status == PlanItemStatus.AUTHORIZABLE]
        if not rows:
            continue
        eligible.append((plan, rows))
        if len(eligible) >= max_active_programs:
            break

    queue: list[WorkQueueItem] = []
    offset = 0
    while eligible and len(queue) < max_items:
        progressed = False
        for plan, rows in eligible:
            if offset >= len(rows) or len(queue) >= max_items:
                continue
            item = rows[offset]
            queue.append(
                WorkQueueItem(
                    queue_id=f"queue-{len(queue) + 1:04d}",
                    engagement_id=plan.engagement_id,
                    test_id=plan.test_id,
                    plan_item_id=item.id,
                    target=item.target,
                    method=item.method,
                    requires_new_permit=True,
                )
            )
            progressed = True
        if not progressed:
            break
        offset += 1

    return WorkQueue(
        created_at=now or datetime.now(UTC),
        max_active_programs=max_active_programs,
        items=queue,
    )
